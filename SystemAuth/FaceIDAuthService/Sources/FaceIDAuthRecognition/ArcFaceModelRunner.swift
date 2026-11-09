import CoreML
import CoreGraphics
import CoreVideo
import Foundation
import Darwin

public enum ArcFaceModelRunnerError: Error, Equatable {
    case notPrivileged
    case unsafeModelPath(String)
    case modelLoadFailed(String)
    case incompatibleModel(String)
    case pixelBufferPoolCreationFailed
    case pixelBufferCreationFailed
    case unexpectedImageSize(width: Int, height: Int)
    case predictionFailed(String)
    case invalidEmbedding
}

/// A strict Core ML runner for the repository's ArcFace w600k_mbf model.
///
/// The caller must supply a canonically aligned 112x112 face image. This type
/// intentionally contains no Vision fallback and never treats a failed model
/// load or prediction as an authentication success.
public final class ArcFaceModelRunner: @unchecked Sendable {
    public static let modelIdentifier = "arcface-w600k_mbf-v1"
    public static let embeddingDimension = 512
    public static let inputSize = 112
    public static let productionModelURL = URL(
        fileURLWithPath: "/Library/Application Support/com.joeqiao.faceid/Models/ArcFace.mlmodelc",
        isDirectory: true
    )

    private static let inputName = "input_image"
    private static let outputName = "embedding"
    private static let maximumBundleBytes: Int64 = 256 * 1024 * 1024
    private static let maximumBundleEntries = 4096

    private let model: MLModel
    private let pixelBufferPool: CVPixelBufferPool
    private let inferenceLock = NSLock()

    /// Production callers must use the default root-owned model location and
    /// keep requireRootOwnership enabled. The relaxed mode exists only for
    /// tests that load the checked-in model from the source checkout.
    public init(
        modelURL: URL = ArcFaceModelRunner.productionModelURL,
        requireRootOwnership: Bool = true
    ) throws {
        if requireRootOwnership && geteuid() != 0 {
            throw ArcFaceModelRunnerError.notPrivileged
        }
        try Self.validateModelBundle(at: modelURL, requireRootOwnership: requireRootOwnership)

        let configuration = MLModelConfiguration()
        configuration.computeUnits = .all

        do {
            model = try MLModel(contentsOf: modelURL, configuration: configuration)
        } catch {
            throw ArcFaceModelRunnerError.modelLoadFailed(error.localizedDescription)
        }

        try Self.validateModelDescription(model.modelDescription)

        let attributes: [String: Any] = [
            kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_32BGRA,
            kCVPixelBufferWidthKey as String: Self.inputSize,
            kCVPixelBufferHeightKey as String: Self.inputSize,
            kCVPixelBufferIOSurfacePropertiesKey as String: [:] as [String: Any]
        ]
        var pool: CVPixelBufferPool?
        let status = CVPixelBufferPoolCreate(
            kCFAllocatorDefault,
            nil,
            attributes as CFDictionary,
            &pool
        )
        guard status == kCVReturnSuccess, let pool else {
            throw ArcFaceModelRunnerError.pixelBufferPoolCreationFailed
        }
        pixelBufferPool = pool
    }

    /// Returns a finite, L2-normalized 512-dimensional ArcFace vector.
    public func embedding(for alignedFace: CGImage) throws -> [Float] {
        guard alignedFace.width == Self.inputSize, alignedFace.height == Self.inputSize else {
            throw ArcFaceModelRunnerError.unexpectedImageSize(
                width: alignedFace.width,
                height: alignedFace.height
            )
        }

        var pixelBufferOut: CVPixelBuffer?
        let status = CVPixelBufferPoolCreatePixelBuffer(
            kCFAllocatorDefault,
            pixelBufferPool,
            &pixelBufferOut
        )
        guard status == kCVReturnSuccess, let pixelBuffer = pixelBufferOut else {
            throw ArcFaceModelRunnerError.pixelBufferCreationFailed
        }

        try Self.render(alignedFace, into: pixelBuffer)
        let input: MLDictionaryFeatureProvider
        do {
            input = try MLDictionaryFeatureProvider(dictionary: [
                Self.inputName: MLFeatureValue(pixelBuffer: pixelBuffer)
            ])
        } catch {
            throw ArcFaceModelRunnerError.predictionFailed(error.localizedDescription)
        }

        let output: MLFeatureProvider
        inferenceLock.lock()
        defer { inferenceLock.unlock() }
        do {
            output = try model.prediction(from: input)
        } catch {
            throw ArcFaceModelRunnerError.predictionFailed(error.localizedDescription)
        }

        guard let array = output.featureValue(for: Self.outputName)?.multiArrayValue,
              array.count == Self.embeddingDimension else {
            throw ArcFaceModelRunnerError.incompatibleModel("expected a 512-element embedding output")
        }

        var vector = [Float](repeating: 0, count: array.count)
        for index in 0..<array.count {
            vector[index] = array[index].floatValue
        }
        guard vector.allSatisfy({ $0.isFinite }) else {
            throw ArcFaceModelRunnerError.invalidEmbedding
        }

        let normSquared = vector.reduce(Float.zero) { $0 + $1 * $1 }
        guard normSquared.isFinite, normSquared > 1.0e-12 else {
            throw ArcFaceModelRunnerError.invalidEmbedding
        }
        let inverseNorm = 1.0 / sqrt(normSquared)
        let normalized = vector.map { $0 * inverseNorm }
        guard normalized.allSatisfy({ $0.isFinite }) else {
            throw ArcFaceModelRunnerError.invalidEmbedding
        }
        return normalized
    }

    private static func validateModelDescription(_ description: MLModelDescription) throws {
        guard let input = description.inputDescriptionsByName[inputName],
              input.type == .image,
              let imageConstraint = input.imageConstraint,
              imageConstraint.pixelsWide == inputSize,
              imageConstraint.pixelsHigh == inputSize else {
            throw ArcFaceModelRunnerError.incompatibleModel("input must be a 112x112 image named input_image")
        }

        guard let output = description.outputDescriptionsByName[outputName],
              output.type == .multiArray,
              let arrayConstraint = output.multiArrayConstraint,
              arrayConstraint.shape.reduce(1, { $0 * $1.intValue }) == embeddingDimension else {
            throw ArcFaceModelRunnerError.incompatibleModel("output must be a 512-element multi-array named embedding")
        }
    }

    private static func render(_ image: CGImage, into pixelBuffer: CVPixelBuffer) throws {
        CVPixelBufferLockBaseAddress(pixelBuffer, [])
        defer { CVPixelBufferUnlockBaseAddress(pixelBuffer, []) }

        guard let baseAddress = CVPixelBufferGetBaseAddress(pixelBuffer),
              let context = CGContext(
                data: baseAddress,
                width: CVPixelBufferGetWidth(pixelBuffer),
                height: CVPixelBufferGetHeight(pixelBuffer),
                bitsPerComponent: 8,
                bytesPerRow: CVPixelBufferGetBytesPerRow(pixelBuffer),
                space: CGColorSpaceCreateDeviceRGB(),
                bitmapInfo: CGBitmapInfo(
                    rawValue: CGImageAlphaInfo.premultipliedFirst.rawValue |
                        CGBitmapInfo.byteOrder32Little.rawValue
                ).rawValue
              ) else {
            throw ArcFaceModelRunnerError.pixelBufferCreationFailed
        }
        context.interpolationQuality = .high
        context.draw(image, in: CGRect(x: 0, y: 0, width: Self.inputSize, height: Self.inputSize))
    }

    /// Reject symlinks, writable ancestors, unexpected file types, and (in
    /// production) anything not owned by root before Core ML opens the bundle.
    private static func validateModelBundle(at url: URL, requireRootOwnership: Bool) throws {
        let standardized = url.standardizedFileURL
        var ancestor = URL(fileURLWithPath: "/", isDirectory: true)
        for component in standardized.pathComponents.dropFirst() {
            ancestor.appendPathComponent(component, isDirectory: true)
            var info = stat()
            guard lstat(ancestor.path, &info) == 0,
                  (info.st_mode & S_IFMT) == S_IFDIR,
                  (info.st_mode & 0o022) == 0,
                  (!requireRootOwnership || info.st_uid == 0) else {
                throw ArcFaceModelRunnerError.unsafeModelPath(ancestor.path)
            }
        }

        var totalBytes: Int64 = 0
        var entryCount = 0
        try validateNode(
            standardized,
            requireRootOwnership: requireRootOwnership,
            totalBytes: &totalBytes,
            entryCount: &entryCount
        )
    }

    private static func validateNode(
        _ url: URL,
        requireRootOwnership: Bool,
        totalBytes: inout Int64,
        entryCount: inout Int
    ) throws {
        entryCount += 1
        guard entryCount <= maximumBundleEntries else {
            throw ArcFaceModelRunnerError.unsafeModelPath("model bundle contains too many entries")
        }

        var info = stat()
        guard lstat(url.path, &info) == 0,
              (info.st_mode & 0o022) == 0,
              (!requireRootOwnership || info.st_uid == 0) else {
            throw ArcFaceModelRunnerError.unsafeModelPath(url.path)
        }

        switch info.st_mode & S_IFMT {
        case S_IFDIR:
            let children: [URL]
            do {
                children = try FileManager.default.contentsOfDirectory(
                    at: url,
                    includingPropertiesForKeys: nil,
                    options: []
                )
            } catch {
                throw ArcFaceModelRunnerError.unsafeModelPath(url.path)
            }
            for child in children {
                try validateNode(
                    child,
                    requireRootOwnership: requireRootOwnership,
                    totalBytes: &totalBytes,
                    entryCount: &entryCount
                )
            }
        case S_IFREG:
            guard info.st_nlink == 1, info.st_size >= 0 else {
                throw ArcFaceModelRunnerError.unsafeModelPath(url.path)
            }
            totalBytes += info.st_size
            guard totalBytes <= maximumBundleBytes else {
                throw ArcFaceModelRunnerError.unsafeModelPath("model bundle exceeds size limit")
            }
        default:
            // Includes symbolic links, sockets, devices, and FIFOs.
            throw ArcFaceModelRunnerError.unsafeModelPath(url.path)
        }
    }
}
