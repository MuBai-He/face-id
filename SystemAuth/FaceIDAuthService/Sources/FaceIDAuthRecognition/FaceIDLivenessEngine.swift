import Foundation

public enum FaceIDLivenessDecision: Equatable, Sendable {
    case pending
    case confirmed
    case denied(String)
}

/// Stateful, deny-first liveness gate for system authentication.
///
/// Unlike the app's light mode, this engine always uses heavy mode: at least
/// one positive 3D/pose/blink cue must fire, and all spoof-deny cues remain
/// active. It also waits for a minimum number of frames and requires the caller
/// to explicitly finish the scan. It is still passive liveness, not a secure
/// random-action challenge and not equivalent to Secure Enclave biometrics.
public final class FaceIDLivenessEngine: @unchecked Sendable {
    public static let minimumFrames = 8
    public static let scanTimeout: TimeInterval = 8.0

    private let lock = NSLock()
    private var frames: [LivenessFrame] = []
    private var evaluator = LivenessEvaluator(
        mode: .heavy,
        tuning: .default,
        enabledCues: Set(LivenessCue.allCases)
    )
    private var firstFrameTime: Date?
    private var lastFrameTime: Date?
    private var observedFrameCount = 0
    private var latchedDecision: FaceIDLivenessDecision?

    public init() {}

    public func reset() {
        lock.lock()
        defer { lock.unlock() }
        frames.removeAll(keepingCapacity: true)
        evaluator = LivenessEvaluator(
            mode: .heavy,
            tuning: .default,
            enabledCues: Set(LivenessCue.allCases)
        )
        firstFrameTime = nil
        lastFrameTime = nil
        observedFrameCount = 0
        latchedDecision = nil
    }

    /// The liveness features are derived inside FaceIDAuthRecognition from the
    /// raw CGImage. Callers cannot submit a precomputed "live" Boolean or
    /// replace the underlying cue readings.
    public func observe(_ recognition: FaceIDRecognitionResult) -> FaceIDLivenessDecision {
        lock.lock()
        defer { lock.unlock() }

        if let latchedDecision {
            return latchedDecision
        }

        let frame = recognition.livenessFrame
        if let lastFrameTime {
            guard frame.timestamp > lastFrameTime else {
                latchedDecision = .denied("non-monotonic frame timestamp")
                return latchedDecision!
            }
            if frame.timestamp.timeIntervalSince(lastFrameTime) > 1.0 {
                latchedDecision = .denied("camera frame gap exceeded limit")
                return latchedDecision!
            }
        } else {
            firstFrameTime = frame.timestamp
        }
        lastFrameTime = frame.timestamp
        observedFrameCount += 1

        if let firstFrameTime,
           frame.timestamp.timeIntervalSince(firstFrameTime) > Self.scanTimeout {
            latchedDecision = .denied("liveness scan timed out")
            return latchedDecision!
        }

        frames.append(frame)
        frames.removeAll {
            frame.timestamp.timeIntervalSince($0.timestamp) > 2.0
        }

        evaluator.mode = .heavy
        evaluator.tuning = .default
        evaluator.enabledCues = Set(LivenessCue.allCases)

        let geometry = GeometryLiveness.evaluate(frames)
        let readings = LivenessCues.readings(window: frames, geometry: geometry)
        let snapshot = evaluator.observe(readings)

        if case .denied(let cue) = snapshot.decision {
            latchedDecision = .denied(cue.rawValue)
            return latchedDecision!
        }
        if snapshot.decision.isConfirmed && observedFrameCount >= Self.minimumFrames {
            latchedDecision = .confirmed
            return .confirmed
        }
        return .pending
    }

    /// A scan that ends without a heavy-mode confirmation is a denial, never
    /// an implicit success. A later frame cannot revive a finished scan.
    public func finish() -> FaceIDLivenessDecision {
        lock.lock()
        defer { lock.unlock() }
        if let latchedDecision {
            return latchedDecision
        }
        latchedDecision = .denied("liveness challenge incomplete")
        return latchedDecision!
    }
}
