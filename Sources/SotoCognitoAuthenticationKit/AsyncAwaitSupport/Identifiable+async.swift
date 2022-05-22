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

#if compiler(>=5.5) && canImport(_Concurrency)

import NIO
import SotoCognitoIdentity

/// Public interface functions for authenticating with CognitoIdentityProvider and generating access and id tokens.
extension CognitoIdentifiable {
    // MARK: Async/Await Methods

    /// Return an Cognito Identity identity id from an id token
    /// - parameters:
    ///     - idToken: Id token returned from authenticating a user
    ///     - on: Event loop request is running on.
    /// - returns:
    ///     Identity id
    public func getIdentityId(
        idToken: String,
        logger: Logger = AWSClient.loggingDisabled,
        on eventLoop: EventLoop? = nil
    ) async throws -> String {
        do {
            let request = CognitoIdentity.GetIdInput(identityPoolId: self.configuration.identityPoolId, logins: [self.configuration.identityProvider: idToken])
            let response = try await self.configuration.cognitoIdentity.getId(request, logger: logger, on: eventLoop)
            guard let identityId = response.identityId else { throw SotoCognitoError.unexpectedResult(reason: "AWS did not return an identity id") }
            return identityId
        } catch {
            throw self.translateError(error: error)
        }
    }

    /// Get AWS credentials from an identity id
    /// - parameters:
    ///     - identityId: Identity id returned from `getIdentityId`
    ///     - idToken: Id token returned from authenticating a user
    ///     - on: Event loop request is running on.
    /// - returns:
    ///     AWS credentials
    public func getCredentialForIdentity(
        identityId: String,
        idToken: String,
        logger: Logger = AWSClient.loggingDisabled,
        on eventLoop: EventLoop? = nil
    ) async throws -> CognitoIdentity.Credentials {
        do {
            let request = CognitoIdentity.GetCredentialsForIdentityInput(
                identityId: identityId,
                logins: [self.configuration.identityProvider: idToken]
            )
            let response = try await self.configuration.cognitoIdentity.getCredentialsForIdentity(
                request,
                logger: logger,
                on: eventLoop
            )
            guard let credentials = response.credentials else { throw SotoCognitoError.unexpectedResult(reason: "AWS did not supply any credentials") }
            return credentials
        } catch {
            throw self.translateError(error: error)
        }
    }
}

#endif // compiler(>=5.5) && canImport(_Concurrency)
