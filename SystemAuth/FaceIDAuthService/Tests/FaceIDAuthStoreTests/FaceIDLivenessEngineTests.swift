import Foundation
import XCTest
@testable import FaceIDAuthRecognition

final class FaceIDLivenessEngineTests: XCTestCase {
    private func recognition(at timestamp: Date) -> FaceIDRecognitionResult {
        let frame = LivenessFrame(
            timestamp: timestamp,
            landmarks: [],
            interocularDistance: nil,
            yaw: nil,
            leftEyeAspectRatio: nil,
            rightEyeAspectRatio: nil,
            noseOffsetRatio: nil,
            hasReliableLandmarks: false,
            deviceOverlapFraction: nil,
            glare: nil
        )
        return FaceIDRecognitionResult(
            embedding: [Float](repeating: 1 / sqrt(512), count: 512),
            captureQuality: 0.9,
            alignment: .fivePoint,
            livenessFrame: frame
        )
    }

    func testNoPositiveCueNeverAutoConfirms() {
        let engine = FaceIDLivenessEngine()
        let start = Date(timeIntervalSince1970: 1_800_000_000)
        for index in 0..<12 {
            XCTAssertEqual(engine.observe(recognition(at: start.addingTimeInterval(Double(index) * 0.1))), .pending)
        }
        XCTAssertEqual(engine.finish(), .denied("liveness challenge incomplete"))
    }

    func testNonMonotonicFramesFailClosed() {
        let engine = FaceIDLivenessEngine()
        let start = Date(timeIntervalSince1970: 1_800_000_000)
        XCTAssertEqual(engine.observe(recognition(at: start)), .pending)
        XCTAssertEqual(engine.observe(recognition(at: start)), .denied("non-monotonic frame timestamp"))
    }

    func testLargeFrameGapFailsClosed() {
        let engine = FaceIDLivenessEngine()
        let start = Date(timeIntervalSince1970: 1_800_000_000)
        XCTAssertEqual(engine.observe(recognition(at: start)), .pending)
        XCTAssertEqual(
            engine.observe(recognition(at: start.addingTimeInterval(1.1))),
            .denied("camera frame gap exceeded limit")
        )
    }

    func testHeavyEvaluatorRequiresPositiveCue() {
        var evaluator = LivenessEvaluator(
            mode: .heavy,
            tuning: .default,
            enabledCues: Set(LivenessCue.allCases)
        )
        var snapshot = LivenessSnapshot.empty
        for _ in 0..<12 {
            snapshot = evaluator.observe([:])
        }
        XCTAssertEqual(snapshot.decision, .pending)
    }

    func testDenyCueOverridesEarlierConfirmation() {
        var evaluator = LivenessEvaluator(
            mode: .heavy,
            tuning: .default,
            enabledCues: Set(LivenessCue.allCases)
        )
        var snapshot = evaluator.observe([.blink: CueReading(level: 1, confidence: 1)])
        XCTAssertEqual(snapshot.decision, .confirmed(by: .blink))

        for _ in 0..<3 {
            snapshot = evaluator.observe([.deviceDetected: CueReading(level: 0.8, confidence: 1)])
        }
        XCTAssertEqual(snapshot.decision, .denied(by: .deviceDetected))
    }
}
