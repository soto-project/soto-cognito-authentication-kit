//===----------------------------------------------------------------------===//
//
// This source file is part of the Soto for AWS open source project
//
// Copyright (c) 2021 the Soto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of Soto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import SotoCognitoIdentity
import SotoCognitoIdentityProvider

/// Cognito authentication method used by `CredentialProviderFactory.cognitoUserPool`.
public struct CognitoAuthenticationMethod {
    public typealias Method = (CognitoAuthenticatable, String) async throws -> CognitoAuthenticateResponse
    let authenticate: Method

    public init(authenticate: @escaping Method) {
        self.authenticate = authenticate
    }
}

extension CognitoAuthenticationMethod {
    /// Authenticate with password
    public static func password(_ password: String) -> Self {
        return .init { authenticatable, userName in
            try await authenticatable.authenticate(
                username: userName,
                password: password,
                clientMetadata: nil,
                context: nil
            )
        }
    }

    /// Authenticate with refresh token
    public static func refreshToken(_ token: String) -> Self {
        return .init { authenticatable, userName in
            try await authenticatable.refresh(
                username: userName,
                refreshToken: token,
                clientMetadata: nil,
                context: nil
            )
        }
    }
}

actor UserPoolIdentityProvider: IdentityProvider {
    let userPoolIdentityProvider: String
    let authenticatable: CognitoAuthenticatable
    let respondToChallenge: (@Sendable (CognitoChallengeName, [String: String]?, Error?) async throws -> [String: String]?)?
    let maxChallengeResponseAttempts: Int
    let identityProviderContext: IdentityProviderFactory.Context
    var currentUserName: String
    var currentAuthentication: CognitoAuthenticationMethod
    var challengeResponseAttempts: Int

    init(
        userName: String,
        authentication: CognitoAuthenticationMethod,
        userPoolId: String,
        identityProviderContext: IdentityProviderFactory.Context,
        clientId: String,
        clientSecret: String? = nil,
        respondToChallenge: (@Sendable (CognitoChallengeName, [String: String]?, Error?) async throws -> [String: String]?)?,
        maxChallengeResponseAttempts: Int = 4
    ) {
        self.userPoolIdentityProvider = "cognito-idp.\(identityProviderContext.cognitoIdentity.region).amazonaws.com/\(userPoolId)"
        let cognitoIdentityProvider = CognitoIdentityProvider(
            client: identityProviderContext.cognitoIdentity.client,
            region: identityProviderContext.cognitoIdentity.region
        )
        let configuration = CognitoConfiguration(
            userPoolId: userPoolId,
            clientId: clientId,
            clientSecret: clientSecret,
            cognitoIDP: cognitoIdentityProvider,
            adminClient: false
        )
        self.identityProviderContext = identityProviderContext
        self.authenticatable = CognitoAuthenticatable(configuration: configuration)
        self.currentUserName = userName
        self.currentAuthentication = authentication
        self.respondToChallenge = respondToChallenge
        self.maxChallengeResponseAttempts = maxChallengeResponseAttempts
        self.challengeResponseAttempts = 0
    }

    func getIdentity(logger: Logging.Logger) async throws -> CognitoIdentity.IdentityParams {
        let idToken: String
        do {
            let authResponse = try await self.currentAuthentication.authenticate(self.authenticatable, self.currentUserName)
            idToken = try await self.respondToAuthenticateResponse(authResponse, challenge: nil)
        } catch {
            idToken = try await self.respondToAuthenticateError(error, challenge: nil)
        }
        let logins = [userPoolIdentityProvider: idToken]
        let request = CognitoIdentity.GetIdInput(identityPoolId: self.identityProviderContext.identityPoolId, logins: logins)
        let response = try await self.identityProviderContext.cognitoIdentity.getId(request, logger: self.identityProviderContext.logger)
        guard let identityId = response.identityId else { throw CredentialProviderError.noProvider }
        return .init(id: identityId, logins: logins)
    }

    func respondToAuthenticateResponse(_ response: CognitoAuthenticateResponse, challenge: CognitoAuthenticateResponse.ChallengedResponse?) async throws -> String {
        switch response {
        case .authenticated(let response):
            guard let idToken = response.idToken else {
                throw SotoCognitoError.unexpectedResult(reason: "Authenticated response does not authentication tokens")
            }
            // if we received a refresh token then this is not via a refresh authentication and we should attempt to get
            // the username from the access token to ensure we have the correct username
            if let refreshToken = response.refreshToken {
                self.currentAuthentication = .refreshToken(refreshToken)
                if let accessToken = response.accessToken {
                    let accessAuthenticateResponse = try await authenticatable.authenticate(accessToken: accessToken)
                    self.currentUserName = accessAuthenticateResponse.username
                }
            }
            return idToken
        case .challenged(let challenge):
            return try await self.respondToChallenge(challenge, error: nil)
        }
    }

    func respondToAuthenticateError(_ error: Error, challenge: CognitoAuthenticateResponse.ChallengedResponse?) async throws -> String {
        if let error = error as? CognitoIdentityProviderErrorType, let prevChallenge = challenge {
            return try await self.respondToChallenge(prevChallenge, error: error)
        } else {
            throw error
        }
    }

    func respondToChallenge(_ challenge: CognitoAuthenticateResponse.ChallengedResponse, error: Error?) async throws -> String {
        guard let challengeName = challenge.name else {
            throw SotoCognitoError.unexpectedResult(reason: "Challenge response does not have valid challenge name")
        }
        guard let respondToChallenge = respondToChallenge else {
            throw SotoCognitoError.unauthorized(reason: "Did not respond to challenge \(challengeName)")
        }
        guard self.challengeResponseAttempts < self.maxChallengeResponseAttempts else {
            throw SotoCognitoError.unauthorized(reason: "Failed to produce valid response to challenge \(challengeName)")
        }
        do {
            self.challengeResponseAttempts += 1
            let parameters = try await respondToChallenge(challengeName, challenge.parameters, error)
            guard let parameters = parameters else {
                throw SotoCognitoError.unauthorized(reason: "Did not respond to challenge \(challengeName)")
            }
            let challengeResponse = try await authenticatable.respondToChallenge(username: self.currentUserName, name: challengeName, responses: parameters, session: challenge.session)
            return try await self.respondToAuthenticateResponse(challengeResponse, challenge: challenge)
        } catch {
            return try await self.respondToAuthenticateError(error, challenge: challenge)
        }
    }
}

extension IdentityProviderFactory {
    /// Identity provider using Cognito userpools
    static func cognitoUserPool(
        userName: String,
        authentication: CognitoAuthenticationMethod,
        userPoolId: String,
        clientId: String,
        clientSecret: String? = nil,
        respondToChallenge: (@Sendable (CognitoChallengeName, [String: String]?, Error?) async throws -> [String: String]?)? = nil,
        maxChallengeResponseAttempts: Int = 4
    ) -> Self {
        return .custom { context in
            return UserPoolIdentityProvider(
                userName: userName,
                authentication: authentication,
                userPoolId: userPoolId,
                identityProviderContext: context,
                clientId: clientId,
                clientSecret: clientSecret,
                respondToChallenge: respondToChallenge,
                maxChallengeResponseAttempts: maxChallengeResponseAttempts
            )
        }
    }
}

extension CredentialProviderFactory {
    /// Credential provider using Cognito userpool authentication
    ///
    /// You can authenticate with Cognito UserPools with various methods. Options available
    /// include `.password` and `.refreshToken`. If you import `SotoCognitoAuthenticationSRP`
    /// you also get secure remote password authentication with `.srp`.
    ///
    /// When authenticating, Cognito might respond with a challenge. Many of these challenges
    /// require user input. The `respondToChallenge` closure allows you to provide challenge
    /// response parameters. The respond to challenge closure is called with a challenge type
    /// the related input parameters, an error is the last challenge response produced an error and
    /// the `EventLoop` everything is running on. If you return `nil` that is considered a failed
    /// challenge and an error will be thrown. Below is a list of common challenges with the
    /// expected parameters to be returned.
    /// `.newPasswordRequired`: requires `NEW_PASSWORD`
    /// `.smsMfa`: `SMS_MFA_CODE`
    ///
    /// - Parameters:
    ///   - userName: user name to use for authentication
    ///   - authentication: Authentication method.
    ///   - userPoolId: Cognito UserPool ID
    ///   - clientId: Cognito UserPool client ID
    ///   - clientSecret: Cognito UserPool client secret
    ///   - identityPoolId: Cognito Identity pool if
    ///   - region: Region userpool and identity pool are in
    ///   - respondToChallenge: Respond to login challenge method
    ///   - logger: Logger
    public static func cognitoUserPool(
        userName: String,
        authentication: CognitoAuthenticationMethod,
        userPoolId: String,
        clientId: String,
        clientSecret: String? = nil,
        identityPoolId: String,
        region: Region,
        respondToChallenge: (@Sendable (CognitoChallengeName, [String: String]?, Error?) async throws -> [String: String]?)? = nil,
        maxChallengeResponseAttempts: Int = 4,
        logger: Logger = AWSClient.loggingDisabled
    ) -> CredentialProviderFactory {
        let identityProvider = IdentityProviderFactory.cognitoUserPool(
            userName: userName,
            authentication: authentication,
            userPoolId: userPoolId,
            clientId: clientId,
            clientSecret: clientSecret,
            respondToChallenge: respondToChallenge,
            maxChallengeResponseAttempts: maxChallengeResponseAttempts
        )
        return .cognitoIdentity(
            identityPoolId: identityPoolId,
            identityProvider: identityProvider,
            region: region,
            logger: logger
        )
    }
}
