// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "FaceIDAuthService",
    platforms: [.macOS(.v15)],
    products: [
        .library(name: "FaceIDAuthStore", targets: ["FaceIDAuthStore"])
    ],
    targets: [
        .target(name: "FaceIDAuthStore"),
        .testTarget(name: "FaceIDAuthStoreTests", dependencies: ["FaceIDAuthStore"])
    ]
)
