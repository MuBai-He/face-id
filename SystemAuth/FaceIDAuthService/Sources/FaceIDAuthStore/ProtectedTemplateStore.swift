import CryptoKit
import Foundation
import Security
import Darwin

public struct FaceTemplateSample: Codable, Equatable, Sendable {
    public let embedding: [Float]
    public let capturedAt: Date

    public init(embedding: [Float], capturedAt: Date = Date()) {
        self.embedding = embedding
        self.capturedAt = capturedAt
    }
}

public struct FaceTemplateIdentity: Codable, Equatable, Sendable {
    public let id: UUID
    public let uid: UInt32
    public var name: String
    public let modelIdentifier: String
    public let embeddingDimension: Int
    public var samples: [FaceTemplateSample]
    public let createdAt: Date
    public var isEnabled: Bool

    public init(
        id: UUID = UUID(),
        uid: UInt32,
        name: String,
        modelIdentifier: String = "arcface-w600k_mbf-v1",
        embeddingDimension: Int = 512,
        samples: [FaceTemplateSample],
        createdAt: Date = Date(),
        isEnabled: Bool = true
    ) {
        self.id = id
        self.uid = uid
        self.name = name
        self.modelIdentifier = modelIdentifier
        self.embeddingDimension = embeddingDimension
        self.samples = samples
        self.createdAt = createdAt
        self.isEnabled = isEnabled
    }
}

public enum ProtectedTemplateStoreError: Error, Equatable {
    case notPrivileged
    case unsafeDirectory
    case unsafeKeyFile
    case keyGenerationFailed
    case storageFailure
    case corruptedStore
    case unsupportedFormat
    case invalidTemplate(String)
    case storeTooLarge
}

private struct TemplateDocument: Codable {
    let version: Int
    let identities: [FaceTemplateIdentity]
}

public final class ProtectedTemplateStore {
    public static let productionDirectory = URL(
        fileURLWithPath: "/Library/Application Support/com.joeqiao.faceid",
        isDirectory: true
    )

    private static let keyFileName = "templates.key"
    private static let storeFileName = "templates.v1.enc"
    private static let keyLength = 32
    private static let maximumStoreBytes = 1_048_576
    private static let maximumIdentities = 16
    private static let maximumSamplesPerIdentity = 64
    private static let expectedModelIdentifier = "arcface-w600k_mbf-v1"
    private static let expectedDimension = 512

    private let directoryURL: URL
    private let expectedOwnerUID: uid_t
    private let key: SymmetricKey
    private let lock = NSLock()

    /// Production must use owner UID 0. The owner override exists for isolated tests.
    public init(
        directoryURL: URL = ProtectedTemplateStore.productionDirectory,
        expectedOwnerUID: uid_t = 0
    ) throws {
        self.directoryURL = directoryURL
        self.expectedOwnerUID = expectedOwnerUID
        if expectedOwnerUID == 0 && geteuid() != 0 {
            throw ProtectedTemplateStoreError.notPrivileged
        }
        try Self.prepareDirectory(directoryURL, ownerUID: expectedOwnerUID)
        self.key = try Self.loadOrCreateKey(
            at: directoryURL.appendingPathComponent(Self.keyFileName),
            ownerUID: expectedOwnerUID
        )
    }

    public func load() throws -> [FaceTemplateIdentity] {
        lock.lock()
        defer { lock.unlock() }

        let url = directoryURL.appendingPathComponent(Self.storeFileName)
        var info = stat()
        guard lstat(url.path, &info) == 0 else {
            if errno == ENOENT { return [] }
            throw ProtectedTemplateStoreError.storageFailure
        }
        guard (info.st_mode & S_IFMT) == S_IFREG,
              info.st_uid == expectedOwnerUID,
              (info.st_mode & 0o077) == 0,
              info.st_nlink == 1,
              info.st_size > 0,
              info.st_size <= Self.maximumStoreBytes else {
            throw ProtectedTemplateStoreError.corruptedStore
        }

        let encrypted: Data
        do {
            encrypted = try Data(contentsOf: url)
        } catch {
            throw ProtectedTemplateStoreError.storageFailure
        }
        guard encrypted.count <= Self.maximumStoreBytes,
              let sealedBox = try? AES.GCM.SealedBox(combined: encrypted),
              let plaintext = try? AES.GCM.open(sealedBox, using: key) else {
            throw ProtectedTemplateStoreError.corruptedStore
        }

        let document: TemplateDocument
        do {
            document = try JSONDecoder().decode(TemplateDocument.self, from: plaintext)
        } catch {
            throw ProtectedTemplateStoreError.corruptedStore
        }
        guard document.version == 1 else {
            throw ProtectedTemplateStoreError.unsupportedFormat
        }
        try Self.validate(document.identities)
        return document.identities
    }

    /// The daemon must independently validate an administrator authorization right
    /// before calling this method to enroll, replace, or disable a template.
    public func save(_ identities: [FaceTemplateIdentity]) throws {
        try Self.validate(identities)
        let document = TemplateDocument(version: 1, identities: identities)
        let plaintext: Data
        do {
            plaintext = try JSONEncoder().encode(document)
        } catch {
            throw ProtectedTemplateStoreError.storageFailure
        }
        guard plaintext.count <= Self.maximumStoreBytes else {
            throw ProtectedTemplateStoreError.storeTooLarge
        }

        let sealedBox: AES.GCM.SealedBox
        do {
            sealedBox = try AES.GCM.seal(plaintext, using: key)
        } catch {
            throw ProtectedTemplateStoreError.storageFailure
        }
        guard let encrypted = sealedBox.combined,
              encrypted.count <= Self.maximumStoreBytes else {
            throw ProtectedTemplateStoreError.storeTooLarge
        }

        lock.lock()
        defer { lock.unlock() }

        let destination = directoryURL.appendingPathComponent(Self.storeFileName)
        let temporary = directoryURL.appendingPathComponent(".templates-\\(UUID().uuidString).tmp")
        do {
            try encrypted.write(to: temporary, options: .atomic)
            guard chmod(temporary.path, 0o600) == 0 else {
                try? FileManager.default.removeItem(at: temporary)
                throw ProtectedTemplateStoreError.storageFailure
            }
            guard rename(temporary.path, destination.path) == 0 else {
                try? FileManager.default.removeItem(at: temporary)
                throw ProtectedTemplateStoreError.storageFailure
            }
            let directoryFD = open(directoryURL.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
            if directoryFD >= 0 {
                _ = fsync(directoryFD)
                close(directoryFD)
            }
        } catch let error as ProtectedTemplateStoreError {
            throw error
        } catch {
            try? FileManager.default.removeItem(at: temporary)
            throw ProtectedTemplateStoreError.storageFailure
        }
    }

    public func deleteAll() throws {
        lock.lock()
        defer { lock.unlock() }
        let url = directoryURL.appendingPathComponent(Self.storeFileName)
        if unlink(url.path) != 0 && errno != ENOENT {
            throw ProtectedTemplateStoreError.storageFailure
        }
    }

    private static func validate(_ identities: [FaceTemplateIdentity]) throws {
        guard identities.count <= maximumIdentities else {
            throw ProtectedTemplateStoreError.invalidTemplate("too many identities")
        }
        var ids = Set<UUID>()
        for identity in identities {
            guard identity.uid != 0,
                  ids.insert(identity.id).inserted,
                  !identity.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                  identity.name.count <= 64,
                  identity.modelIdentifier == expectedModelIdentifier,
                  identity.embeddingDimension == expectedDimension,
                  !identity.samples.isEmpty,
                  identity.samples.count <= maximumSamplesPerIdentity else {
                throw ProtectedTemplateStoreError.invalidTemplate("invalid identity metadata")
            }
            for sample in identity.samples {
                guard sample.embedding.count == expectedDimension,
                      sample.embedding.allSatisfy(\\.isFinite) else {
                    throw ProtectedTemplateStoreError.invalidTemplate("invalid embedding")
                }
                let norm = sample.embedding.reduce(Float.zero) { $0 + $1 * $1 }
                guard norm.isFinite, abs(norm - 1.0) <= 0.05 else {
                    throw ProtectedTemplateStoreError.invalidTemplate("embedding must be L2-normalized")
                }
            }
        }
    }

    private static func prepareDirectory(_ url: URL, ownerUID: uid_t) throws {
        if mkdir(url.path, 0o700) != 0 && errno != EEXIST {
            throw ProtectedTemplateStoreError.storageFailure
        }
        var info = stat()
        guard lstat(url.path, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFDIR,
              info.st_uid == ownerUID,
              (info.st_mode & 0o077) == 0 else {
            throw ProtectedTemplateStoreError.unsafeDirectory
        }
    }

    private static func loadOrCreateKey(at url: URL, ownerUID: uid_t) throws -> SymmetricKey {
        var info = stat()
        if lstat(url.path, &info) != 0 {
            guard errno == ENOENT else { throw ProtectedTemplateStoreError.storageFailure }
            var bytes = [UInt8](repeating: 0, count: keyLength)
            guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
                throw ProtectedTemplateStoreError.keyGenerationFailed
            }
            let fd = open(url.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
            if fd < 0 {
                if errno == EEXIST {
                    return try readKey(at: url, ownerUID: ownerUID)
                }
                throw ProtectedTemplateStoreError.storageFailure
            }
            var offset = 0
            while offset < bytes.count {
                let written = bytes.withUnsafeBytes { raw in
                    write(fd, raw.baseAddress!.advanced(by: offset), bytes.count - offset)
                }
                if written < 0 && errno == EINTR { continue }
                if written <= 0 {
                    close(fd)
                    _ = unlink(url.path)
                    throw ProtectedTemplateStoreError.storageFailure
                }
                offset += written
            }
            guard fsync(fd) == 0, close(fd) == 0 else {
                _ = unlink(url.path)
                throw ProtectedTemplateStoreError.storageFailure
            }
            return SymmetricKey(data: Data(bytes))
        }
        return try readKey(at: url, ownerUID: ownerUID)
    }

    private static func readKey(at url: URL, ownerUID: uid_t) throws -> SymmetricKey {
        let fd = open(url.path, O_RDONLY | O_NOFOLLOW)
        guard fd >= 0 else { throw ProtectedTemplateStoreError.storageFailure }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFREG,
              info.st_uid == ownerUID,
              (info.st_mode & 0o077) == 0,
              info.st_nlink == 1,
              info.st_size == keyLength else {
            throw ProtectedTemplateStoreError.unsafeKeyFile
        }
        var bytes = [UInt8](repeating: 0, count: keyLength)
        var offset = 0
        while offset < bytes.count {
            let count = bytes.withUnsafeMutableBytes { raw in
                read(fd, raw.baseAddress!.advanced(by: offset), bytes.count - offset)
            }
            if count < 0 && errno == EINTR { continue }
            if count <= 0 { throw ProtectedTemplateStoreError.storageFailure }
            offset += count
        }
        return SymmetricKey(data: Data(bytes))
    }
}
