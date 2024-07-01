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

import AsyncHTTPClient
import Foundation
import JWTKit
import NIO

/// Struct returned when authenticating an access token
public struct CognitoAccessToken: Codable, Sendable {
    public let username: String
    public let subject: UUID
    public let expirationTime: Date

    private enum CodingKeys: String, CodingKey {
        case username
        case subject = "sub"
        case expirationTime = "exp"
    }
}

/// Public interface functions for authenticating with CognitoIdentityProvider access and id tokens
public extension CognitoAuthenticatable {
    /// Verify id Token JWT and return contents
    ///
    /// This function verifies the id token signature, verifies it was issued by your user pool, it was generated for your application client, that it hasn't
    /// expired and that it is an id token.
    /// Then it fills out the placeholder type `Payload`with values from the id token. The list of standard list of claims found in an id token are
    /// detailed in the [OpenID spec](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims) . Your
    /// `Payload` type needs to decode using these tags, plus the AWS specific "cognito:username" tag and any custom tags you have setup
    /// for the user pool.
    /// - parameters:
    ///     - idToken: Id token, returned from login
    ///     - on: Event loop to run on
    /// - returns:
    ///     Payload structure.
    func authenticate<Payload: Codable & Sendable>(
        idToken: String,
        logger: Logger = AWSClient.loggingDisabled
    ) async throws -> Payload {
        let signers = try await loadSigners(region: configuration.region, logger: logger)
        let jwtPayload = try await signers.verify(idToken, as: VerifiedToken<IdTokenVerifier, Payload>.self)
        guard jwtPayload.token.audience == self.configuration.clientId else { throw SotoCognitoError.unauthorized(reason: "invalid token") }
        guard jwtPayload.token.issuer == "https://cognito-idp.\(self.configuration.region.rawValue).amazonaws.com/\(self.configuration.userPoolId)" else {
            throw SotoCognitoError.unauthorized(reason: "invalid token")
        }
        return jwtPayload.payload
    }

    /// Verify access token JWT and return contents
    ///
    /// This function verifies the access token signature, verifies it was issued by your user pool, that it hasn't expired and that it is an access token.
    /// - parameters:
    ///     - accessToken: Access token, returned from login
    ///     - on: Event loop to run on
    /// - returns:
    ///     Structure with the username and UUID for the user.
    func authenticate(
        accessToken: String,
        logger: Logger = AWSClient.loggingDisabled
    ) async throws -> CognitoAccessToken {
        let signers = try await loadSigners(region: configuration.region, logger: logger)
        let jwtPayload = try await signers.verify(accessToken, as: VerifiedToken<AccessTokenVerifier, CognitoAccessToken>.self)
        guard jwtPayload.token.issuer == "https://cognito-idp.\(self.configuration.region.rawValue).amazonaws.com/\(self.configuration.userPoolId)" else {
            throw SotoCognitoError.unauthorized(reason: "invalid token")
        }
        return jwtPayload.payload
    }
}

extension CognitoAuthenticatable {
    /// load JSON web keys and create JWT signers from them
    func loadSigners(
        region: Region,
        logger: Logger = AWSClient.loggingDisabled
    ) async throws -> JWTKeyCollection {
        // check we haven't already loaded the jwt signing key set
        if let jwtSigners = self.jwtSigners {
            return jwtSigners
        }

        logger.debug("Load jwks.json")
        let jwtSignersURL = URL(string: "https://cognito-idp.\(configuration.region.rawValue).amazonaws.com/\(configuration.userPoolId)/.well-known/jwks.json")!
        let httpClient = configuration.cognitoIDP.client.httpClient
        let request = AWSHTTPRequest(url: jwtSignersURL, method: .GET, headers: [:], body: .init())
        let response = try await httpClient.execute(
            request: request,
            timeout: .seconds(20),
            logger: logger
        )
        let signers = JWTKeyCollection()
        let data = try await response.body.collect(upTo: 1_000_000)
        try await signers.use(jwksJSON: String(buffer: data))
        self.jwtSigners = signers
        return signers
    }
}
