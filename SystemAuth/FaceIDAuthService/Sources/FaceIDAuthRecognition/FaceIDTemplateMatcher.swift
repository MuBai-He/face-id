import Foundation
import FaceIDAuthStore

public enum FaceIDTemplateMatcherError: Error, Equatable {
    case invalidRequestedUID
    case invalidThreshold
    case invalidQueryEmbedding
}

public struct FaceIDTemplateMatch: Equatable, Sendable {
    public let identityID: UUID
    public let uid: UInt32
    public let topKSampleSimilarity: Float
    public let maxSampleSimilarity: Float
    public let centroidSimilarity: Float
}

/// Deterministic ArcFace template matching for the privileged authentication path.
///
/// The requested UID is an explicit input and is matched against the UID stored
/// with each template. A caller must never use one account's face to satisfy a
/// different account's PAM request.
public enum FaceIDTemplateMatcher {
    public static let minimumEnrollmentSamples = 3
    public static let topKSampleCount = 3
    public static let centroidSimilaritySlack: Float = 0.12

    /// Returns the highest-scoring enabled identity belonging to requestedUID.
    ///
    /// The threshold is deliberately required at the call site. The system
    /// authentication service must choose a value only after collecting real
    /// false-accept/false-reject data; the app's UI threshold is not silently
    /// inherited as a system security policy.
    public static func bestMatch(
        embedding: [Float],
        requestedUID: UInt32,
        identities: [FaceTemplateIdentity],
        threshold: Float,
        minimumSamples: Int = minimumEnrollmentSamples
    ) throws -> FaceIDTemplateMatch? {
        guard requestedUID != 0 else {
            throw FaceIDTemplateMatcherError.invalidRequestedUID
        }
        guard threshold.isFinite, threshold >= 0.30, threshold <= 1,
              minimumSamples >= topKSampleCount else {
            throw FaceIDTemplateMatcherError.invalidThreshold
        }
        guard isValidUnitVector(embedding) else {
            throw FaceIDTemplateMatcherError.invalidQueryEmbedding
        }

        let candidates = identities.compactMap { identity -> FaceIDTemplateMatch? in
            guard identity.uid == requestedUID,
                  identity.isEnabled,
                  identity.modelIdentifier == ArcFaceModelRunner.modelIdentifier,
                  identity.embeddingDimension == ArcFaceModelRunner.embeddingDimension,
                  identity.samples.count >= minimumSamples else {
                return nil
            }

            let samples = identity.samples.map(\.embedding)
            guard samples.allSatisfy(isValidUnitVector) else { return nil }
            guard let centroid = normalizedAverage(samples) else { return nil }

            let similarities = samples
                .map { cosineSimilarity(embedding, $0) }
                .sorted(by: >)
            let topK = similarities.prefix(topKSampleCount)
            guard topK.count == topKSampleCount else { return nil }

            let topKMean = topK.reduce(Float.zero, +) / Float(topKSampleCount)
            let maxSample = similarities.first ?? 0
            let centroidScore = cosineSimilarity(embedding, centroid)

            guard topKMean >= threshold,
                  centroidScore >= threshold - centroidSimilaritySlack else {
                return nil
            }

            return FaceIDTemplateMatch(
                identityID: identity.id,
                uid: identity.uid,
                topKSampleSimilarity: topKMean,
                maxSampleSimilarity: maxSample,
                centroidSimilarity: centroidScore
            )
        }

        return candidates.max { $0.topKSampleSimilarity < $1.topKSampleSimilarity }
    }

    private static func isValidUnitVector(_ vector: [Float]) -> Bool {
        guard vector.count == ArcFaceModelRunner.embeddingDimension,
              vector.allSatisfy(\.isFinite) else {
            return false
        }
        let normSquared = vector.reduce(Float.zero) { $0 + $1 * $1 }
        guard normSquared.isFinite, normSquared > 1.0e-12 else { return false }
        let norm = sqrt(normSquared)
        return abs(norm - 1.0) <= 0.05
    }

    private static func normalizedAverage(_ vectors: [[Float]]) -> [Float]? {
        guard let first = vectors.first, !first.isEmpty else { return nil }
        var sum = [Float](repeating: 0, count: first.count)
        for vector in vectors {
            let normSquared = vector.reduce(Float.zero) { $0 + $1 * $1 }
            guard normSquared.isFinite, normSquared > 1.0e-12 else { return nil }
            let inverseNorm = 1.0 / sqrt(normSquared)
            for index in 0..<vector.count {
                sum[index] += vector[index] * inverseNorm
            }
        }
        let mean = sum.map { $0 / Float(vectors.count) }
        let normSquared = mean.reduce(Float.zero) { $0 + $1 * $1 }
        guard normSquared.isFinite, normSquared > 1.0e-12 else { return nil }
        let inverseNorm = 1.0 / sqrt(normSquared)
        return mean.map { $0 * inverseNorm }
    }

    private static func cosineSimilarity(_ lhs: [Float], _ rhs: [Float]) -> Float {
        guard lhs.count == rhs.count, !lhs.isEmpty else { return -1 }
        return zip(lhs, rhs).reduce(Float.zero) { $0 + $1.0 * $1.1 }
    }
}
