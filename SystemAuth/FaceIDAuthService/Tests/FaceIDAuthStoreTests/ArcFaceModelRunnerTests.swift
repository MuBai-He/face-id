import CoreGraphics
import Foundation
import Darwin
import XCTest
@testable import FaceIDAuthRecognition

final class ArcFaceModelRunnerTests: XCTestCase {
    private var repositoryRoot: URL {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 {
            url.deleteLastPathComponent()
        }
        return url
    }

    private var modelURL: URL {
        repositoryRoot.appendingPathComponent("FaceID/Models/ArcFace.mlmodelc", isDirectory: true)
    }

    private func makeImage(width: Int = 112, height: Int = 112) throws -> CGImage {
        let bytes = Data(repeating: 127, count: width * height * 4)
        guard let provider = CGDataProvider(data: bytes as CFData),
              let image = CGImage(
                width: width,
                height: height,
                bitsPerComponent: 8,
                bitsPerPixel: 32,
                bytesPerRow: width * 4,
                space: CGColorSpaceCreateDeviceRGB(),
                bitmapInfo: CGBitmapInfo(rawValue: CGImageAlphaInfo.premultipliedLast.rawValue),
                provider: provider,
                decode: nil,
                shouldInterpolate: false,
                intent: .defaultIntent
              ) else {
            throw NSError(domain: "ArcFaceModelRunnerTests", code: 1)
        }
        return image
    }

    func testLoadsCheckedInModelAndProducesNormalizedEmbedding() throws {
        XCTAssertTrue(FileManager.default.fileExists(atPath: modelURL.path))
        let runner = try ArcFaceModelRunner(modelURL: modelURL, requireRootOwnership: false)
        let embedding = try runner.embedding(for: makeImage())

        XCTAssertEqual(embedding.count, ArcFaceModelRunner.embeddingDimension)
        XCTAssertTrue(embedding.allSatisfy(\.isFinite))
        let norm = sqrt(embedding.reduce(Float.zero) { $0 + $1 * $1 })
        XCTAssertEqual(norm, 1.0, accuracy: 0.001)
    }

    func testRejectsImageWithWrongDimensions() throws {
        let runner = try ArcFaceModelRunner(modelURL: modelURL, requireRootOwnership: false)
        XCTAssertThrowsError(try runner.embedding(for: makeImage(width: 111, height: 112))) { error in
            guard case ArcFaceModelRunnerError.unexpectedImageSize(width: 111, height: 112) = error else {
                return XCTFail("Unexpected error: \(error)")
            }
        }
    }

    func testRejectsSymlinkedModelBundle() throws {
        let link = FileManager.default.temporaryDirectory
            .appendingPathComponent("arcface-model-link-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: link) }
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: modelURL)
        XCTAssertThrowsError(try ArcFaceModelRunner(modelURL: link, requireRootOwnership: false))
    }

    func testProductionModeRequiresRootProcess() throws {
        guard getuid() != 0 else { throw XCTSkip("test process is already root") }
        XCTAssertThrowsError(try ArcFaceModelRunner(modelURL: modelURL, requireRootOwnership: true)) { error in
            XCTAssertEqual(error as? ArcFaceModelRunnerError, .notPrivileged)
        }
    }

    func testRejectsMissingModelBundle() throws {
        let missing = FileManager.default.temporaryDirectory
            .appendingPathComponent("missing-arcface-\(UUID().uuidString)", isDirectory: true)
        XCTAssertThrowsError(try ArcFaceModelRunner(modelURL: missing, requireRootOwnership: false))
    }
}
