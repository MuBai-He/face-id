// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "FaceIDAuthService",
    platforms: [.macOS(.v15)],
    products: [
        .library(name: "FaceIDAuthStore", targets: ["FaceIDAuthStore"]),
        .library(name: "FaceIDAuthRecognition", targets: ["FaceIDAuthRecognition"])
    ],
    targets: [
        .target(name: "FaceIDAuthStore"),
        .target(name: "FaceIDAuthRecognition"),
        .testTarget(
            name: "FaceIDAuthStoreTests",
            dependencies: ["FaceIDAuthStore", "FaceIDAuthRecognition"]
        )
    ]
)
