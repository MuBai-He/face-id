import Foundation
import Darwin
import XCTest
@testable import FaceIDAuthStore

final class ProtectedTemplateStoreTests: XCTestCase {
    private func makeDirectory() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("faceid-store-\\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        XCTAssertEqual(chmod(root.path, 0o700), 0)
        return root
    }

    private func identity(uid: UInt32 = 501) -> FaceTemplateIdentity {
        let vector = [Float](repeating: 1 / sqrt(512), count: 512)
        return FaceTemplateIdentity(
            uid: uid,
            name: "Primary",
            samples: [FaceTemplateSample(embedding: vector)]
        )
    }

    func testEmptyStoreLoadsAsEmpty() throws {
        let directory = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try ProtectedTemplateStore(directoryURL: directory, expectedOwnerUID: getuid())
        XCTAssertTrue(try store.load().isEmpty)
    }

    func testEncryptedRoundTrip() throws {
        let directory = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try ProtectedTemplateStore(directoryURL: directory, expectedOwnerUID: getuid())
        let expected = [identity()]
        try store.save(expected)
        XCTAssertEqual(try store.load(), expected)

        let ciphertext = try Data(contentsOf: directory.appendingPathComponent("templates.v1.enc"))
        XCTAssertFalse(String(decoding: ciphertext, as: UTF8.self).contains("Primary"))
    }

    func testStoreAndKeyArePrivate() throws {
        let directory = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try ProtectedTemplateStore(directoryURL: directory, expectedOwnerUID: getuid())
        try store.save([identity()])
        for name in ["templates.key", "templates.v1.enc"] {
            var info = stat()
            XCTAssertEqual(lstat(directory.appendingPathComponent(name).path, &info), 0)
            XCTAssertEqual(info.st_mode & 0o077, 0)
            XCTAssertEqual(info.st_uid, getuid())
        }
    }

    func testTamperedCiphertextIsRejected() throws {
        let directory = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try ProtectedTemplateStore(directoryURL: directory, expectedOwnerUID: getuid())
        try store.save([identity()])
        let url = directory.appendingPathComponent("templates.v1.enc")
        var bytes = try Data(contentsOf: url)
        bytes[bytes.count / 2] ^= 0x40
        try bytes.write(to: url, options: .atomic)
        XCTAssertThrowsError(try store.load())
    }

    func testSymlinkDirectoryIsRejected() throws {
        let parent = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: parent) }
        let target = parent.appendingPathComponent("target", isDirectory: true)
        let link = parent.appendingPathComponent("link", isDirectory: true)
        try FileManager.default.createDirectory(at: target, withIntermediateDirectories: true)
        XCTAssertEqual(chmod(target.path, 0o700), 0)
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
        XCTAssertThrowsError(try ProtectedTemplateStore(directoryURL: link, expectedOwnerUID: getuid()))
    }

    func testNonNormalizedEmbeddingIsRejected() throws {
        let directory = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try ProtectedTemplateStore(directoryURL: directory, expectedOwnerUID: getuid())
        let invalid = FaceTemplateIdentity(
            uid: 501,
            name: "Invalid",
            samples: [FaceTemplateSample(embedding: [Float](repeating: 0, count: 512))]
        )
        XCTAssertThrowsError(try store.save([invalid]))
    }

    func testWrongModelIsRejected() throws {
        let directory = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try ProtectedTemplateStore(directoryURL: directory, expectedOwnerUID: getuid())
        let invalid = FaceTemplateIdentity(
            uid: 501,
            name: "Wrong model",
            modelIdentifier: "vision-feature-print",
            samples: [FaceTemplateSample(embedding: identity().samples[0].embedding)]
        )
        XCTAssertThrowsError(try store.save([invalid]))
    }

    func testRootIdentityIsRejected() throws {
        let directory = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try ProtectedTemplateStore(directoryURL: directory, expectedOwnerUID: getuid())
        XCTAssertThrowsError(try store.save([identity(uid: 0)]))
    }
}
