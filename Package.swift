// swift-tools-version:5.1
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "AWSCognitoAuthentication",
    products: [
        .library(name: "AWSCognitoAuthentication", targets: ["AWSCognitoAuthentication"]),
    ],
    dependencies: [
        .package(url: "https://github.com/swift-aws/aws-sdk-swift.git", .upToNextMajor(from: "3.0.0")),
        .package(url: "https://github.com/vapor/vapor.git", .upToNextMajor(from: "3.0.0")),
        .package(url: "https://github.com/vapor/auth.git", .upToNextMajor(from: "2.0.0")),
        .package(url: "https://github.com/vapor/jwt-kit.git", .upToNextMajor(from: "3.0.0"))
    ],
    targets: [
        .target(name: "AWSCognitoAuthentication",
                dependencies: [
                    "Authentication",
                    "CognitoIdentityProvider",
                    "Vapor",
                    "JWT"
            ]
        ),
        .testTarget(name: "AWSCognitoAuthenticationTests", dependencies: ["AWSCognitoAuthentication"]),
    ]
)
