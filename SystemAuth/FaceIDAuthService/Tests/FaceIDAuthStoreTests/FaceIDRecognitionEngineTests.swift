import CoreGraphics
import Foundation
import XCTest
@testable import FaceIDAuthRecognition

final class FaceIDRecognitionEngineTests: XCTestCase {
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

    private func blankFrame() throws -> CGImage {
        let width = 640
        let height = 480
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
            throw NSError(domain: "FaceIDRecognitionEngineTests", code: 1)
        }
        return image
    }

    func testBlankFrameCannotProduceAuthenticationEmbedding() throws {
        let engine = try FaceIDRecognitionEngine(modelURL: modelURL, requireRootOwnership: false)
        XCTAssertThrowsError(try engine.recognize(in: blankFrame())) { error in
            XCTAssertEqual(error as? FaceIDRecognitionError, .noFaceDetected)
        }
    }
}
