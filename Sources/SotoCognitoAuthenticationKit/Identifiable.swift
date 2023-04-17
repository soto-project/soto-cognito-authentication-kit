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

import NIO
import SotoCognitoIdentity

public final class CognitoIdentifiable: Sendable {
    // MARK: Member variables

    /// Configuration
    public let configuration: CognitoIdentityConfiguration

    // MARK: Initialization

    public init(configuration: CognitoIdentityConfiguration) {
        self.configuration = configuration
    }

    // MARK: Methods

    /// Return an Cognito Identity identity id from an id token
    /// - parameters:
    ///     - idToken: Id token returned from authenticating a user
    ///     - on: Event loop request is running on.
    /// - returns:
    ///     Event Loop Future returning the identity id as a String
    public func getIdentityId(
        idToken: String,
        logger: Logger = AWSClient.loggingDisabled,
        on eventLoop: EventLoop? = nil
    ) -> EventLoopFuture<String> {
        let eventLoop = eventLoop ?? self.configuration.cognitoIdentity.eventLoopGroup.next()
        let request = CognitoIdentity.GetIdInput(identityPoolId: self.configuration.identityPoolId, logins: [self.configuration.identityProvider: idToken])
        return self.configuration.cognitoIdentity.getId(request, logger: logger, on: eventLoop)
            .flatMapErrorThrowing { error in
                throw self.translateError(error: error)
            }
            .flatMapThrowing { response in
                guard let identityId = response.identityId else { throw SotoCognitoError.unexpectedResult(reason: "AWS did not return an identity id") }
                return identityId
            }
            .hop(to: eventLoop)
    }

    /// Get AWS credentials from an identity id
    /// - parameters:
    ///     - identityId: Identity id returned from `getIdentityId`
    ///     - idToken: Id token returned from authenticating a user
    ///     - on: Event loop request is running on.
    /// - returns:
    ///     Event loop future returning AWS credentials
    public func getCredentialForIdentity(
        identityId: String,
        idToken: String,
        logger: Logger = AWSClient.loggingDisabled,
        on eventLoop: EventLoop? = nil
    ) -> EventLoopFuture<CognitoIdentity.Credentials> {
        let eventLoop = eventLoop ?? self.configuration.cognitoIdentity.eventLoopGroup.next()
        let request = CognitoIdentity.GetCredentialsForIdentityInput(identityId: identityId, logins: [self.configuration.identityProvider: idToken])
        return self.configuration.cognitoIdentity.getCredentialsForIdentity(request, logger: logger, on: eventLoop)
            .flatMapErrorThrowing { error in
                throw self.translateError(error: error)
            }
            .flatMapThrowing { response in
                guard let credentials = response.credentials else { throw SotoCognitoError.unexpectedResult(reason: "AWS did not supply any credentials") }
                return credentials
            }
            .hop(to: eventLoop)
    }
}

extension CognitoIdentifiable {
    /// Translate error from one thrown by Soto
    func translateError(error: Error) -> Error {
        switch error {
        case let error as CognitoIdentityErrorType where error == .notAuthorizedException:
            return SotoCognitoError.unauthorized(reason: error.message)

        default:
            return error
        }
    }
}
