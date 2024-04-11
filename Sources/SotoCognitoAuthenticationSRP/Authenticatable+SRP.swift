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

import BigNum
import Crypto
import Foundation
import NIO
import SotoCognitoAuthenticationKit

extension CognitoAuthenticatable {
    // MARK: Secure Remote Password

    /// authenticate using SRP
    ///
    /// This function combines the `initiateAuth`` and `respondToAuthChallenge` calls. If the initiateAuth returns
    /// a challenge that is not the SRP password verifier then the provided closure `respondToChallenge` is called.
    /// You should return a challenge response from this call, or if you do not know how to respond then return `nil`.
    ///
    /// - parameters:
    ///     - username: user name for user
    ///     - password: password for user
    ///     - clientMetadata: A map of custom key-value pairs that you can provide as input for AWS Lambda custom workflows
    ///     - context: Context data for this request
    ///     - respondToChallenge: Function which returns challenge response parameters given a challenge, or the last challenge and the error it generated
    ///     - maxChallengeResponseAttempts: Maximum number of times we are allowed to respond to challenges
    ///     - logger: Logger
    /// - returns:
    ///     An authentication response. This can contain a challenge which the user has to fulfill before being allowed to login, or authentication access, id and refresh keys
    public func authenticateSRP(
        username: String,
        password: String,
        clientMetadata: [String: String]? = nil,
        context: CognitoContextData? = nil,
        respondToChallenge: @escaping @Sendable (CognitoChallengeName, [String: String]?, Error?) async throws -> [String: String]?,
        maxChallengeResponseAttempts: Int = 4,
        logger: Logger = AWSClient.loggingDisabled
    ) async throws -> CognitoAuthenticateResponse.AuthenticatedResponse {
        let srp = SRP<SHA256>()
        var authParameters: [String: String] = [
            "USERNAME": username,
            "SRP_A": srp.A.hex,
        ]
        authParameters["SECRET_HASH"] = secretHash(username: username)

        return try await self.authRequest(
            username: username,
            authFlow: .userSrpAuth,
            authParameters: authParameters,
            clientMetadata: clientMetadata,
            context: context,
            respondToChallenge: { name, parameters, error in
                switch name {
                case .passwordVerifier:
                    return try self.respondToSRPChallenge(parameters, username: username, password: password, srp: srp)
                default:
                    return try await respondToChallenge(name, parameters, error)
                }
            },
            maxChallengeResponseAttempts: maxChallengeResponseAttempts,
            logger: logger
        )
    }

    /// authenticate using SRP
    ///
    /// - parameters:
    ///     - username: user name for user
    ///     - password: password for user
    ///     - clientMetadata: A map of custom key-value pairs that you can provide as input for AWS Lambda custom workflows
    ///     - context: Context data for this request
    ///     - logger: Logger
    /// - returns:
    ///     An authentication response. This can contain a challenge which the user has to fulfill before being allowed to login, or authentication access, id and refresh keys
    public func authenticateSRP(
        username: String,
        password: String,
        clientMetadata: [String: String]? = nil,
        context: CognitoContextData? = nil,
        logger: Logger = AWSClient.loggingDisabled
    ) async throws -> CognitoAuthenticateResponse {
        let srp = SRP<SHA256>()
        var authParameters: [String: String] = [
            "USERNAME": username,
            "SRP_A": srp.A.hex,
        ]
        authParameters["SECRET_HASH"] = secretHash(username: username)

        let response = try await self.initiateAuthRequest(
            authFlow: .userSrpAuth,
            authParameters: authParameters,
            clientMetadata: clientMetadata,
            context: context,
            logger: logger
        )

        switch response {
        case .challenged(let challenge):
            switch challenge.name {
            case .passwordVerifier:
                let authResponse = try respondToSRPChallenge(challenge.parameters, username: username, password: password, srp: srp)
                return try await self.respondToChallenge(
                    username: username,
                    name: .passwordVerifier,
                    responses: authResponse,
                    session: challenge.session,
                    context: context,
                    logger: logger
                )
            case .some:
                throw SotoCognitoError.unexpectedResult(reason: "Received unexpected challenge")
            case .none:
                throw SotoCognitoError.unexpectedResult(reason: "Received empty challenge")
            }
        case .authenticated:
            return response
        }
    }

    /// Generate response to SRP challenge
    ///
    /// See https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol for details of SRP protocol
    /// - Parameters:
    ///   - parameters: Parameters from AWS
    ///   - username: Username
    ///   - password: Password
    ///   - srp: SRP values used to initiate process
    /// - Returns: Response to SRP challenge
    func respondToSRPChallenge(_ parameters: [String: String]?, username: String, password: String, srp: SRP<SHA256>) throws -> [String: String] {
        guard let parameters,
              let saltHex = parameters["SALT"],
              let salt = BigNum(hex: saltHex)?.bytes,
              let secretBlockBase64 = parameters["SECRET_BLOCK"],
              let secretBlock = Data(base64Encoded: secretBlockBase64),
              let dataB = parameters["SRP_B"]
        else {
            throw SotoCognitoError.unexpectedResult(reason: "AWS did not provide all the data required to do SRP authentication")
        }

        let srpUsername = parameters["USER_ID_FOR_SRP"] ?? username
        let userPoolName = self.configuration.userPoolId.split(separator: "_")[1]
        guard let B = BigNum(hex: dataB) else {
            throw SotoCognitoError.invalidPublicKey
        }

        // get key
        guard let key = srp.getPasswordAuthenticationKey(username: "\(userPoolName)\(srpUsername)", password: password, B: B, salt: salt) else {
            throw SotoCognitoError.invalidPublicKey
        }

        let dateFormatter = DateFormatter()
        // cognito expects the dateformat to have the timezone as UTC
        dateFormatter.dateFormat = "EEE MMM d HH:mm:ss 'UTC' yyyy"
        dateFormatter.timeZone = TimeZone(identifier: "UTC")
        // cognito expects the dateformat to be in English
        dateFormatter.locale = Locale(identifier: "en_US_POSIX")
        let timestamp = dateFormatter.string(from: Date())

        // construct claim
        let claim = HMAC<SHA256>.authenticationCode(for: Data("\(userPoolName)\(srpUsername)".utf8) + secretBlock + Data(timestamp.utf8), using: SymmetricKey(data: key))

        var authResponse: [String: String] = [
            "USERNAME": srpUsername,
            "PASSWORD_CLAIM_SECRET_BLOCK": secretBlockBase64,
            "PASSWORD_CLAIM_SIGNATURE": Data(claim).base64EncodedString(),
            "TIMESTAMP": timestamp,
        ]
        authResponse["SECRET_HASH"] = self.secretHash(username: username)
        return authResponse
    }
}
