// swift-tools-version:5.2
//===----------------------------------------------------------------------===//
//
// This source file is part of the Soto for AWS open source project
//
// Copyright (c) 2020-2021 the Soto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of Soto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "soto-cognito-authentication-kit",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13),
        .tvOS(.v13),
    ],
    products: [
        .library(name: "SotoCognitoAuthenticationKit", targets: ["SotoCognitoAuthenticationKit"]),
        .library(name: "SotoCognitoAuthenticationSRP", targets: ["SotoCognitoAuthenticationSRP"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", .upToNextMajor(from: "1.0.0")),
        .package(url: "https://github.com/soto-project/soto.git", from: "6.0.0"),
        .package(url: "https://github.com/swift-server/async-http-client.git", from: "1.10.0"),
        .package(url: "https://github.com/vapor/jwt-kit.git", .upToNextMajor(from: "4.2.6")),
        // for SRP
        .package(url: "https://github.com/adam-fowler/big-num.git", .upToNextMajor(from: "2.0.0")),
    ],
    targets: [
        .target(
            name: "SotoCognitoAuthenticationKit",
            dependencies: [
                .product(name: "SotoCognitoIdentity", package: "soto"),
                .product(name: "SotoCognitoIdentityProvider", package: "soto"),
                .product(name: "AsyncHTTPClient", package: "async-http-client"),
                .product(name: "JWTKit", package: "jwt-kit"),
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
        .testTarget(name: "SotoCognitoAuthenticationKitTests", dependencies: ["SotoCognitoAuthenticationKit"]),

        .target(
            name: "SotoCognitoAuthenticationSRP",
            dependencies: [
                .product(name: "BigNum", package: "big-num"),
                .target(name: "SotoCognitoAuthenticationKit"),
            ]
        ),
        .testTarget(name: "SotoCognitoAuthenticationSRPTests", dependencies: ["SotoCognitoAuthenticationSRP"]),
    ]
)
