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
public struct CognitoAuthenticationMethod: Sendable {
    public struct Context: Sendable {
        public let authenticatable: CognitoAuthenticatable
        public let userName: String
        public let respondToChallenge: @Sendable (CognitoChallengeName, [String: String]?, Error?) async throws -> [String: String]?
        public let maxChallengeResponseAttempts: Int
        public let logger: Logger

        public init(
            authenticatable: CognitoAuthenticatable,
            userName: String,
            respondToChallenge: @escaping @Sendable (CognitoChallengeName, [String: String]?, Error?) async throws -> [String: String]?,
            maxChallengeResponseAttempts: Int,
            logger: Logger
        ) {
            self.authenticatable = authenticatable
            self.userName = userName
            self.respondToChallenge = respondToChallenge
            self.maxChallengeResponseAttempts = maxChallengeResponseAttempts
            self.logger = logger
        }
    }

    public typealias Method = @Sendable (Context) async throws -> CognitoAuthenticateResponse.AuthenticatedResponse
    let authenticate: Method

    public init(authenticate: @escaping Method) {
        self.authenticate = authenticate
    }
}

extension CognitoAuthenticationMethod {
    /// Authenticate with password
    public static func password(_ password: String) -> Self {
        return .init { context in
            try await context.authenticatable.authenticate(
                username: context.userName,
                password: password,
                clientMetadata: nil,
                context: nil,
                respondToChallenge: context.respondToChallenge,
                maxChallengeResponseAttempts: context.maxChallengeResponseAttempts,
                logger: context.logger
            )
        }
    }

    /// Authenticate with refresh token
    public static func refreshToken(_ token: String) -> Self {
        return .init { context in
            try await context.authenticatable.refresh(
                username: context.userName,
                refreshToken: token,
                clientMetadata: nil,
                context: nil,
                respondToChallenge: context.respondToChallenge,
                maxChallengeResponseAttempts: context.maxChallengeResponseAttempts,
                logger: context.logger
            )
        }
    }
}

/// Identity provider using Cognito UserPools
actor UserPoolIdentityProvider: IdentityProvider {
    let userPoolIdentityProvider: String
    let authenticatable: CognitoAuthenticatable
    let respondToChallenge: @Sendable (CognitoChallengeName, [String: String]?, Error?) async throws -> [String: String]?
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
        respondToChallenge: @escaping @Sendable (CognitoChallengeName, [String: String]?, Error?) async throws -> [String: String]? = { _, _, _ in nil },
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

    /// Authenticate with Cognito UserPools
    ///
    /// - Get Identity token from Cognito UserPools
    /// - Get Id from using this token
    /// - Return identity params which can be used to get credentials
    func getIdentity(logger: Logging.Logger) async throws -> CognitoIdentity.IdentityParams {
        let context = CognitoAuthenticationMethod.Context(
            authenticatable: self.authenticatable,
            userName: self.currentUserName,
            respondToChallenge: self.respondToChallenge,
            maxChallengeResponseAttempts: self.maxChallengeResponseAttempts,
            logger: logger
        )
        let authResponse = try await self.currentAuthentication.authenticate(context)
        guard let idToken = authResponse.idToken else {
            throw SotoCognitoError.unexpectedResult(reason: "Authenticated response does not authentication tokens")
        }

        // if we received a refresh token then this is not via a refresh authentication and we should attempt to get
        // the username from the access token to ensure we have the correct username
        if let refreshToken = authResponse.refreshToken {
            self.currentAuthentication = .refreshToken(refreshToken)
            if let accessToken = authResponse.accessToken {
                let accessAuthenticateResponse = try await authenticatable.authenticate(accessToken: accessToken, logger: logger)
                self.currentUserName = accessAuthenticateResponse.username
            }
        }

        let logins = [userPoolIdentityProvider: idToken]
        let request = CognitoIdentity.GetIdInput(identityPoolId: self.identityProviderContext.identityPoolId, logins: logins)
        let idResponse = try await self.identityProviderContext.cognitoIdentity.getId(request, logger: logger)
        guard let identityId = idResponse.identityId else { throw CredentialProviderError.noProvider }
        return .init(id: identityId, logins: logins)
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
        respondToChallenge: @escaping @Sendable (CognitoChallengeName, [String: String]?, Error?) async throws -> [String: String]? = { _, _, _ in nil },
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
        respondToChallenge: @escaping @Sendable (CognitoChallengeName, [String: String]?, Error?) async throws -> [String: String]? = { _, _, _ in nil },
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
