// swift-tools-version:5.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "aws-cognito-authentication-kit",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13),
    ],
    products: [
        .library(name: "AWSCognitoAuthenticationKit", targets: ["AWSCognitoAuthenticationKit"]),
        .library(name: "AWSCognitoAuthenticationSRP", targets: ["AWSCognitoAuthenticationSRP"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", .upToNextMajor(from: "1.0.0")),
        .package(url: "https://github.com/swift-aws/aws-sdk-swift.git", .branch("master")),
        .package(url: "https://github.com/vapor/jwt-kit.git", .upToNextMajor(from: "4.0.0")),
        // for SRP
        .package(url: "https://github.com/adam-fowler/big-num.git", .upToNextMajor(from: "2.0.0")),
    ],
    targets: [
        .target(name: "AWSCognitoAuthenticationKit",
                dependencies: [
                    .product(name: "AWSCognitoIdentity", package: "aws-sdk-swift"),
                    .product(name: "AWSCognitoIdentityProvider", package: "aws-sdk-swift"),
                    .product(name: "JWTKit", package: "jwt-kit"),
                    .product(name: "Crypto", package: "swift-crypto")
            ]
        ),
        .testTarget(name: "AWSCognitoAuthenticationKitTests", dependencies: ["AWSCognitoAuthenticationKit"]),

        .target(name: "AWSCognitoAuthenticationSRP",
                dependencies: [
                    .product(name: "BigNum", package: "big-num"),
                    .target(name: "AWSCognitoAuthenticationKit")
            ]
        ),
        .testTarget(name: "AWSCognitoAuthenticationSRPTests", dependencies: ["AWSCognitoAuthenticationSRP"]),
    ]
)
