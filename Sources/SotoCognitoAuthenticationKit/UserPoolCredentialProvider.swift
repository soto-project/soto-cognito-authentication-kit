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
    public typealias Method = (CognitoAuthenticatable, String, EventLoop) -> EventLoopFuture<CognitoAuthenticateResponse>
    let authenticate: Method

    public init(authenticate: @escaping Method) {
        self.authenticate = authenticate
    }
}

extension CognitoAuthenticationMethod {
    /// Authenticate with password
    public static func password(_ password: String) -> Self {
        return .init { authenticatable, userName, eventLoop in
            authenticatable.authenticate(
                username: userName,
                password: password,
                clientMetadata: nil,
                context: nil,
                on: eventLoop
            )
        }
    }

    /// Authenticate with refresh token
    public static func refreshToken(_ token: String) -> Self {
        return .init { authenticatable, userName, eventLoop in
            authenticatable.refresh(
                username: userName,
                refreshToken: token,
                clientMetadata: nil,
                context: nil,
                on: eventLoop
            )
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
        respondToChallenge: ((CognitoChallengeName, [String: String]?, Error?, EventLoop) -> EventLoopFuture<[String: String]?>)? = nil,
        maxChallengeResponseAttempts: Int = 4
    ) -> Self {
        var currentAuthentication = authentication
        var currentUserName = userName
        var challengeResponseAttempts = 0
        return externalIdentityProvider { context in
            let userPoolIdentityProvider = "cognito-idp.\(context.region).amazonaws.com/\(userPoolId)"
            let cognitoIdentityProvider = CognitoIdentityProvider(client: context.client, region: context.region)
            let configuration = CognitoConfiguration(
                userPoolId: userPoolId,
                clientId: clientId,
                clientSecret: clientSecret,
                cognitoIDP: cognitoIdentityProvider,
                adminClient: false
            )
            let authenticatable = CognitoAuthenticatable(configuration: configuration)
            let tokenPromise = context.eventLoop.makePromise(of: String.self)

            func _respond(to challenge: CognitoAuthenticateResponse.ChallengedResponse, error: Error?) {
                guard let challengeName = challenge.name
                else {
                    tokenPromise.fail(SotoCognitoError.unexpectedResult(reason: "Challenge response does not have valid challenge name"))
                    return
                }
                guard let respondToChallenge = respondToChallenge else {
                    tokenPromise.fail(SotoCognitoError.unauthorized(reason: "Did not respond to challenge \(challengeName)"))
                    return
                }
                guard challengeResponseAttempts < maxChallengeResponseAttempts else {
                    tokenPromise.fail(SotoCognitoError.unauthorized(reason: "Failed to produce valid response to challenge \(challengeName)"))
                    return
                }
                respondToChallenge(challengeName, challenge.parameters, error, context.eventLoop)
                    .flatMap { parameters in
                        // if nil parameters is sent then throw did not respond error
                        guard let parameters = parameters else {
                            return context.eventLoop.makeFailedFuture(SotoCognitoError.unauthorized(reason: "Did not respond to challenge \(challengeName)"))
                        }
                        return authenticatable.respondToChallenge(username: currentUserName, name: challengeName, responses: parameters, session: challenge.session)
                    }
                    .whenComplete { (result: Result<CognitoAuthenticateResponse, Error>) -> Void in
                        challengeResponseAttempts += 1
                        _respond(to: result, challenge: challenge)
                    }
            }

            func _respond(to result: Result<CognitoAuthenticateResponse, Error>, challenge: CognitoAuthenticateResponse.ChallengedResponse?) {
                switch result {
                case .success(.authenticated(let response)):
                    guard let idToken = response.idToken else {
                        tokenPromise.fail(SotoCognitoError.unexpectedResult(reason: "Authenticated response does not authentication tokens"))
                        return
                    }
                    // if we received a refresh token then this is not via a refresh authentication and we should attempt to get
                    // the username from the access token to ensure we have the correct username
                    if let refreshToken = response.refreshToken {
                        currentAuthentication = .refreshToken(refreshToken)
                        if let accessToken = response.accessToken {
                            authenticatable.authenticate(accessToken: accessToken, on: context.eventLoop)
                                .whenComplete { result in
                                    switch result {
                                    case .success(let response):
                                        currentUserName = response.username
                                        tokenPromise.succeed(idToken)
                                    case .failure(let error):
                                        tokenPromise.fail(error)
                                    }
                                }
                        } else {
                            tokenPromise.succeed(idToken)
                        }
                    } else {
                        tokenPromise.succeed(idToken)
                    }

                case .success(.challenged(let challenge)):
                    _respond(to: challenge, error: nil)

                case .failure(let error):
                    if let error = error as? CognitoIdentityProviderErrorType, let prevChallenge = challenge {
                        _respond(to: prevChallenge, error: error)
                    } else {
                        tokenPromise.fail(error)
                    }
                }
            }
            currentAuthentication.authenticate(authenticatable, currentUserName, context.eventLoop).whenComplete { result in
                _respond(to: result, challenge: nil)
            }
            return tokenPromise.futureResult.map { [userPoolIdentityProvider: $0] }
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
        respondToChallenge: ((CognitoChallengeName, [String: String]?, Error?, EventLoop) -> EventLoopFuture<[String: String]?>)? = nil,
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
