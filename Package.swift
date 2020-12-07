// swift-tools-version:5.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "soto-cognito-authentication-kit",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13)
    ],
    products: [
        .library(name: "SotoCognitoAuthenticationKit", targets: ["SotoCognitoAuthenticationKit"]),
        .library(name: "SotoCognitoAuthenticationSRP", targets: ["SotoCognitoAuthenticationSRP"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", .upToNextMajor(from: "1.0.0")),
        .package(url: "https://github.com/soto-project/soto.git", .upToNextMajor(from: "5.0.0")),
        .package(url: "https://github.com/vapor/jwt-kit.git", .upToNextMajor(from: "4.0.0")),
        // for SRP
        .package(url: "https://github.com/adam-fowler/big-num.git", .upToNextMajor(from: "2.0.0")),
    ],
    targets: [
        .target(name: "SotoCognitoAuthenticationKit",
                dependencies: [
                    .product(name: "SotoCognitoIdentity", package: "soto"),
                    .product(name: "SotoCognitoIdentityProvider", package: "soto"),
                    .product(name: "JWTKit", package: "jwt-kit"),
                    .product(name: "Crypto", package: "swift-crypto")
            ]
        ),
        .testTarget(name: "SotoCognitoAuthenticationKitTests", dependencies: ["SotoCognitoAuthenticationKit"]),

        .target(name: "SotoCognitoAuthenticationSRP",
                dependencies: [
                    .product(name: "BigNum", package: "big-num"),
                    .target(name: "SotoCognitoAuthenticationKit")
            ]
        ),
        .testTarget(name: "SotoCognitoAuthenticationSRPTests", dependencies: ["SotoCognitoAuthenticationSRP"]),
    ]
)
