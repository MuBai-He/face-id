import CoreGraphics
import Foundation

public enum FaceIDRecognitionError: Error, Equatable {
    case noFaceDetected
    case multipleFacesDetected(Int)
    case faceTooSmall
    case captureQualityUnavailable
    case captureQualityTooLow(Float)
    case alignmentFailed
    case insufficientLandmarks
}

public enum FaceIDAlignmentQuality: String, Sendable {
    case fivePoint
    case twoPoint
}

public struct FaceIDRecognitionResult: Sendable {
    /// A unit-length ArcFace vector. It is a biometric feature, not by itself
    /// an authentication decision or proof of liveness.
    public let embedding: [Float]
    public let captureQuality: Float
    public let alignment: FaceIDAlignmentQuality
    let livenessFrame: LivenessFrame
}

public final class FaceIDRecognitionEngine: @unchecked Sendable {
    /// Match the app's existing lower bound for a prominent foreground face.
    public static let minimumFaceWidth: CGFloat = 0.18
    /// Provisional capture-quality floor. Must be calibrated with real users
    /// and false-accept/false-reject testing before enabling system auth.
    public static let minimumCaptureQuality: Float = 0.50

    private let model: ArcFaceModelRunner

    public init(
        modelURL: URL = ArcFaceModelRunner.productionModelURL,
        requireRootOwnership: Bool = true
    ) throws {
        model = try ArcFaceModelRunner(
            modelURL: modelURL,
            requireRootOwnership: requireRootOwnership
        )
    }

    /// Detects exactly one prominent face, requires usable Vision quality and
    /// landmark alignment, then runs ArcFace. It deliberately rejects the
    /// padded-crop fallback and never switches to Vision Feature Print.
    ///
    /// A caller must still combine this output with an independent liveness
    /// decision and the protected template store before approving anything.
    public func recognize(in frame: CGImage) throws -> FaceIDRecognitionResult {
        let faces = try FaceDetector.detectFaces(in: frame)
        guard !faces.isEmpty else {
            throw FaceIDRecognitionError.noFaceDetected
        }
        guard faces.count == 1 else {
            throw FaceIDRecognitionError.multipleFacesDetected(faces.count)
        }

        let face = faces[0]
        guard face.normalizedBoundingBox.width >= Self.minimumFaceWidth else {
            throw FaceIDRecognitionError.faceTooSmall
        }
        guard let quality = face.quality else {
            throw FaceIDRecognitionError.captureQualityUnavailable
        }
        guard quality >= Self.minimumCaptureQuality else {
            throw FaceIDRecognitionError.captureQualityTooLow(quality)
        }
        guard let aligned = FaceAligner.align(face, from: frame) else {
            throw FaceIDRecognitionError.alignmentFailed
        }

        let alignment: FaceIDAlignmentQuality
        switch aligned.tier {
        case .fivePoint:
            alignment = .fivePoint
        case .twoPoint:
            alignment = .twoPoint
        case .paddedCrop:
            throw FaceIDRecognitionError.insufficientLandmarks
        }

        let embedding = try model.embedding(for: aligned.image)
        let livenessFrame = FaceIDLivenessFeatureExtractor.extract(
            face: face,
            frame: frame,
            alignment: alignment
        )
        return FaceIDRecognitionResult(
            embedding: embedding,
            captureQuality: quality,
            alignment: alignment,
            livenessFrame: livenessFrame
        )
    }
}
