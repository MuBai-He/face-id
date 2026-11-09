import Foundation
import XCTest
@testable import FaceIDAuthStore
@testable import FaceIDAuthRecognition

final class FaceIDTemplateMatcherTests: XCTestCase {
    private func vector(_ index: Int) -> [Float] {
        var result = [Float](repeating: 0, count: 512)
        result[index] = 1
        return result
    }

    private func identity(
        uid: UInt32 = 501,
        enabled: Bool = true,
        modelIdentifier: String = ArcFaceModelRunner.modelIdentifier,
        vectors: [[Float]]? = nil
    ) -> FaceTemplateIdentity {
        let samples = (vectors ?? [vector(0), vector(0), vector(0)]).map {
            FaceTemplateSample(embedding: $0)
        }
        return FaceTemplateIdentity(
            uid: uid,
            name: "Primary",
            modelIdentifier: modelIdentifier,
            samples: samples,
            isEnabled: enabled
        )
    }

    func testExactIdentityMatchIsUIDScoped() throws {
        let expected = identity()
        let match = try FaceIDTemplateMatcher.bestMatch(
            embedding: vector(0),
            requestedUID: 501,
            identities: [expected],
            threshold: 0.50
        )
        XCTAssertEqual(match?.identityID, expected.id)
        XCTAssertEqual(match?.uid, 501)
        XCTAssertEqual(match?.topKSampleSimilarity, 1, accuracy: 0.0001)
        XCTAssertEqual(match?.centroidSimilarity, 1, accuracy: 0.0001)
    }

    func testCannotUseAnotherUsersTemplate() throws {
        XCTAssertNil(try FaceIDTemplateMatcher.bestMatch(
            embedding: vector(0),
            requestedUID: 502,
            identities: [identity(uid: 501)],
            threshold: 0.50
        ))
    }

    func testDisabledIdentityCannotMatch() throws {
        XCTAssertNil(try FaceIDTemplateMatcher.bestMatch(
            embedding: vector(0),
            requestedUID: 501,
            identities: [identity(enabled: false)],
            threshold: 0.50
        ))
    }

    func testVisionTemplatesCannotMatch() throws {
        XCTAssertNil(try FaceIDTemplateMatcher.bestMatch(
            embedding: vector(0),
            requestedUID: 501,
            identities: [identity(modelIdentifier: "vision-feature-print-v1")],
            threshold: 0.50
        ))
    }

    func testInsufficientEnrollmentSamplesCannotMatch() throws {
        XCTAssertNil(try FaceIDTemplateMatcher.bestMatch(
            embedding: vector(0),
            requestedUID: 501,
            identities: [identity(vectors: [vector(0), vector(0)])],
            threshold: 0.50
        ))
    }

    func testSingleLuckySampleCannotCarryAnImpostor() throws {
        XCTAssertNil(try FaceIDTemplateMatcher.bestMatch(
            embedding: vector(0),
            requestedUID: 501,
            identities: [identity(vectors: [vector(0), vector(1), vector(1)])],
            threshold: 0.50
        ))
    }

    func testInvalidQueryVectorFailsClosed() {
        XCTAssertThrowsError(try FaceIDTemplateMatcher.bestMatch(
            embedding: [Float](repeating: 0, count: 512),
            requestedUID: 501,
            identities: [identity()],
            threshold: 0.50
        )) { error in
            XCTAssertEqual(error as? FaceIDTemplateMatcherError, .invalidQueryEmbedding)
        }
    }

    func testRootUIDCannotBeMatched() {
        XCTAssertThrowsError(try FaceIDTemplateMatcher.bestMatch(
            embedding: vector(0),
            requestedUID: 0,
            identities: [identity(uid: 0)],
            threshold: 0.50
        )) { error in
            XCTAssertEqual(error as? FaceIDTemplateMatcherError, .invalidRequestedUID)
        }
    }

    func testThresholdMustBeExplicitlyValid() {
        XCTAssertThrowsError(try FaceIDTemplateMatcher.bestMatch(
            embedding: vector(0),
            requestedUID: 501,
            identities: [identity()],
            threshold: 0
        )) { error in
            XCTAssertEqual(error as? FaceIDTemplateMatcherError, .invalidThreshold)
        }
    }
}
