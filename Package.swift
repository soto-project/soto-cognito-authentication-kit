// swift-tools-version:5.1
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "AWSCognitoAuthentication",
    platforms: [.macOS(.v10_14)],
    products: [
        .library(name: "AWSCognitoAuthentication", targets: ["AWSCognitoAuthentication"]),
    ],
    dependencies: [
        .package(url: "https://github.com/swift-aws/aws-sdk-swift.git", .upToNextMajor(from: "4.0.0-rc2")),
        .package(url: "https://github.com/vapor/vapor.git", .upToNextMajor(from: "4.0.0-beta")),
        .package(url: "https://github.com/vapor/jwt-kit.git", .branch("master")),
        // for SRP
        .package(url: "https://github.com/adam-fowler/BigNum.git", .branch("master")),
    ],
    targets: [
        .target(name: "AWSCognitoAuthentication",
                dependencies: [
                    "BigNum",
                    "CognitoIdentity",
                    "CognitoIdentityProvider",
                    "Vapor",
                    "JWTKit"
            ]
        ),
        .testTarget(name: "AWSCognitoAuthenticationTests", dependencies: ["AWSCognitoAuthentication"]),
    ]
)
