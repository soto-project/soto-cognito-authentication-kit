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

public extension CognitoAuthenticatable {
    // MARK: Secure Remote Password

    /// authenticate using SRP
    ///
    /// - parameters:
    ///     - username: user name for user
    ///     - password: password for user
    ///     - clientMetadata: A map of custom key-value pairs that you can provide as input for AWS Lambda custom workflows
    ///     - context: Context data for this request
    ///     - on: Eventloop request should run on.
    /// - returns:
    ///     An authentication response. This can contain a challenge which the user has to fulfill before being allowed to login, or authentication access, id and refresh keys
    func authenticateSRP(
        username: String,
        password: String,
        clientMetadata: [String: String]? = nil,
        context: CognitoContextData? = nil,
        logger: Logger = AWSClient.loggingDisabled,
        on eventLoop: EventLoop? = nil
    ) async throws -> CognitoAuthenticateResponse {
        let srp = SRP<SHA256>()
        var authParameters: [String: String] = [
            "USERNAME": username,
            "SRP_A": srp.A.hex,
        ]
        authParameters["SECRET_HASH"] = secretHash(username: username)

        // print("Parameters \(authParameters)")
        let response = try await self.initiateAuthRequest(
            authFlow: .userSrpAuth,
            authParameters: authParameters,
            clientMetadata: clientMetadata,
            context: context,
            logger: logger,
            on: eventLoop
        )

        // print("Response \(response)")
        guard case .challenged(let challenge) = response,
              let parameters = challenge.parameters,
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
        let timestamp = dateFormatter.string(from: Date())

        // construct claim
        let claim = HMAC<SHA256>.authenticationCode(for: Data("\(userPoolName)\(srpUsername)".utf8) + secretBlock + Data(timestamp.utf8), using: SymmetricKey(data: key))

        // print("claim \(claim.hexdigest())")
        var authResponse: [String: String] = [
            "USERNAME": srpUsername,
            "PASSWORD_CLAIM_SECRET_BLOCK": secretBlockBase64,
            "PASSWORD_CLAIM_SIGNATURE": Data(claim).base64EncodedString(),
            "TIMESTAMP": timestamp,
        ]
        authResponse["SECRET_HASH"] = self.secretHash(username: username)

        return try await self.respondToChallenge(
            username: username,
            name: .passwordVerifier,
            responses: authResponse,
            session: challenge.session,
            context: context,
            logger: logger,
            on: eventLoop
        )
    }
}
