// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "FaceIDAuthService",
    platforms: [.macOS(.v15)],
    products: [
        .library(name: "FaceIDAuthStore", targets: ["FaceIDAuthStore"]),
        .library(name: "FaceIDAuthRecognition", targets: ["FaceIDAuthRecognition"]),
        .library(name: "FaceIDAuthIPC", targets: ["FaceIDAuthIPC"]),
        .executable(name: "faceid-authd", targets: ["FaceIDAuthDaemon"])
    ],
    targets: [
        .target(name: "FaceIDAuthStore"),
        .target(name: "FaceIDAuthRecognition", dependencies: ["FaceIDAuthStore"]),
        .target(name: "FaceIDAuthIPC"),
        .executableTarget(name: "FaceIDAuthDaemon", dependencies: ["FaceIDAuthIPC"]),
        .testTarget(
            name: "FaceIDAuthStoreTests",
            dependencies: ["FaceIDAuthStore", "FaceIDAuthRecognition", "FaceIDAuthIPC"]
        )
    ]
)
