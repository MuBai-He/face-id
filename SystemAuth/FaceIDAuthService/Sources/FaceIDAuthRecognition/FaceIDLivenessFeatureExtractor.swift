import CoreGraphics
import Foundation

nonisolated enum FaceIDLivenessFeatureExtractor {
    /// Derives the app's existing liveness measurements from the full frame.
    /// This runs in the recognition process; the client never supplies scores.
    static func extract(
        face: DetectedFace,
        frame: CGImage,
        alignment: FaceIDAlignmentQuality,
        timestamp: Date = Date()
    ) -> LivenessFrame {
        let deviceOverlap = DeviceBezelDetector.detect(
            in: frame,
            faceBoundingBox: face.boundingBox
        ).faceOverlapFraction
        let faceCrop = FaceDetector.crop(face, from: frame)
        let glare = faceCrop.flatMap { GlareCueExtractor.extract(faceCrop: $0) }

        guard let landmarks = face.landmarks else {
            return LivenessFrame(
                timestamp: timestamp,
                landmarks: [],
                interocularDistance: nil,
                yaw: face.yaw,
                leftEyeAspectRatio: nil,
                rightEyeAspectRatio: nil,
                noseOffsetRatio: nil,
                hasReliableLandmarks: false,
                deviceOverlapFraction: deviceOverlap,
                glare: glare
            )
        }

        let imageSize = face.imageSize
        let points = LandmarkGeometry.allPoints(from: landmarks, imageSize: imageSize)
        let interocular = LandmarkGeometry.interocularDistance(from: landmarks, imageSize: imageSize)
        let leftEAR = landmarks.leftEye.flatMap {
            LandmarkGeometry.eyeAspectRatio(of: $0, imageSize: imageSize)
        }
        let rightEAR = landmarks.rightEye.flatMap {
            LandmarkGeometry.eyeAspectRatio(of: $0, imageSize: imageSize)
        }

        let eyeLeft = LandmarkGeometry.eyeCenter(
            pupil: landmarks.leftPupil,
            eye: landmarks.leftEye,
            imageSize: imageSize
        )
        let eyeRight = LandmarkGeometry.eyeCenter(
            pupil: landmarks.rightPupil,
            eye: landmarks.rightEye,
            imageSize: imageSize
        )

        var noseOffsetRatio: CGFloat?
        if let interocular, interocular > 0,
           let eyeLeft, let eyeRight,
           let nose = landmarks.nose,
           let noseCenter = LandmarkGeometry.centroid(of: nose, imageSize: imageSize) {
            let eyeMidX = (eyeLeft.x + eyeRight.x) / 2
            noseOffsetRatio = (noseCenter.x - eyeMidX) / interocular
        }

        return LivenessFrame(
            timestamp: timestamp,
            landmarks: points,
            interocularDistance: interocular,
            yaw: face.yaw,
            leftEyeAspectRatio: leftEAR,
            rightEyeAspectRatio: rightEAR,
            noseOffsetRatio: noseOffsetRatio,
            hasReliableLandmarks: alignment == .fivePoint,
            deviceOverlapFraction: deviceOverlap,
            glare: glare
        )
    }
}
