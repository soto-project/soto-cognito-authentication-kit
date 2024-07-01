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

import Foundation
import JWTKit

/// JWT Access token
struct AccessTokenVerifier: JWTPayload {
    let expirationTime: Date
    let issuer: String
    let tokenUse: String

    func verify(using algorithm: some JWTAlgorithm) async throws {
        guard self.expirationTime > Date() else { throw SotoCognitoError.unauthorized(reason: "token expired") }
        guard self.tokenUse == "access" else { throw SotoCognitoError.unauthorized(reason: "invalid token") }
    }

    private enum CodingKeys: String, CodingKey {
        case expirationTime = "exp"
        case issuer = "iss"
        case tokenUse = "token_use"
    }
}

/// JWT Id token
struct IdTokenVerifier: JWTPayload {
    let audience: String
    let expirationTime: Date
    let issuer: String
    let tokenUse: String

    func verify(using algorithm: some JWTAlgorithm) async throws {
        guard self.expirationTime > Date() else { throw SotoCognitoError.unauthorized(reason: "token expired") }
        guard self.tokenUse == "id" else { throw SotoCognitoError.unauthorized(reason: "invalid token") }
    }

    private enum CodingKeys: String, CodingKey {
        case audience = "aud"
        case expirationTime = "exp"
        case issuer = "iss"
        case tokenUse = "token_use"
    }
}

/// JWT payload that encapsulates both a verified token and an output payload
struct VerifiedToken<Token: JWTPayload, Payload: Codable & Sendable>: JWTPayload {
    let token: Token
    let payload: Payload

    init(from decoder: Decoder) throws {
        self.token = try Token(from: decoder)
        self.payload = try Payload(from: decoder)
    }

    func verify(using algorithm: some JWTAlgorithm) async throws {
        try await self.token.verify(using: algorithm)
    }
}
