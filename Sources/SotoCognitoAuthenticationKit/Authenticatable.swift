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

import Crypto
import Foundation
import JWTKit
import NIO
import NIOConcurrencyHelpers
@_exported import SotoCognitoIdentityProvider

/// Authentication challenge returned by Cognito
public typealias CognitoChallengeName = CognitoIdentityProvider.ChallengeNameType
/// Cognito user status
public typealias CognitoUserStatusType = CognitoIdentityProvider.UserStatusType

/// Errors thrown by `CognitoAuthenticateResponse`
public enum SotoCognitoError: Error {
    /// Unexpected result return from AWS
    case unexpectedResult(reason: String?)
    /// Unauthorized to run this command
    case unauthorized(reason: String?)
    /// Public key returned by Soto is invalid please try again
    case invalidPublicKey
}

/// Response to `createUser`
public struct CognitoCreateUserResponse: Codable, Sendable {
    /// name of user
    public var userName: String
    /// status of user account
    public var userStatus: CognitoUserStatusType
}

/// Authentication response
public enum CognitoAuthenticateResponse: Codable, Sendable {
    /// Response with authentication details
    case authenticated(AuthenticatedResponse)
    /// Response containing a challenge
    case challenged(ChallengedResponse)

    /// Authenticated Response
    public struct AuthenticatedResponse: Codable, Sendable {
        public let accessToken: String?
        public let idToken: String?
        public let refreshToken: String?
        public let expiresIn: Date?
    }

    /// Response containing an authentication challenge
    public struct ChallengedResponse: Codable, Sendable {
        /// Name of challenge
        public let name: CognitoChallengeName?
        /// Challenge parameters
        public let parameters: [String: String]?
        /// Session id to include in challenge response
        public let session: String?
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        if let authenticated = try container.decodeIfPresent(AuthenticatedResponse.self, forKey: .authenticated) {
            self = .authenticated(authenticated)
        } else if let challenged = try container.decodeIfPresent(ChallengedResponse.self, forKey: .challenged) {
            self = .challenged(challenged)
        } else {
            throw DecodingError.valueNotFound(CognitoAuthenticateResponse.self, .init(codingPath: decoder.codingPath, debugDescription: "No valid response found"))
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .authenticated(let authenticated):
            try container.encode(authenticated, forKey: .authenticated)
        case .challenged(let challenged):
            try container.encode(challenged, forKey: .challenged)
        }
    }

    private enum CodingKeys: String, CodingKey {
        case authenticated
        case challenged
    }
}

/// Public interface functions for authenticating with CognitoIdentityProvider and generating access and id tokens.
public final class CognitoAuthenticatable {
    // MARK: Member variables

    /// Configuration
    public let configuration: CognitoConfiguration
    /// JWT Signers
    var jwtSigners: JWTKeyCollection?

    // MARK: Initialization

    /// Initialize `CognitoAuthenticatable`
    /// - Parameter configuration: cognito authentication configuration
    public init(configuration: CognitoConfiguration) {
        self.configuration = configuration
        self.jwtSigners = nil
    }

    // MARK: Methods

    /// Sign up as AWS Cognito user.
    ///
    /// An email will be sent out with either a confirmation code or a link to confirm the user.
    /// - parameters:
    ///     - username: user name for new user
    ///     - password: password for new user
    ///     - attributes: user attributes. These should be from the list of standard claims detailed in the [OpenID spec](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims). You can include custom attiibutes by prepending them with "custom:".
    ///     - clientMetadata: A map of custom key-value pairs that you can provide as input for AWS Lambda custom workflows
    ///     - logger: logger
    /// - returns:
    ///     Sign up response
    public func signUp(
        username: String,
        password: String,
        attributes: [String: String],
        clientMetadata: [String: String]? = nil,
        logger: Logger = AWSClient.loggingDisabled
    ) async throws -> CognitoIdentityProvider.SignUpResponse {
        let userAttributes = attributes.map { return CognitoIdentityProvider.AttributeType(name: $0.key, value: $0.value) }
        let request = CognitoIdentityProvider.SignUpRequest(
            clientId: self.configuration.clientId,
            clientMetadata: clientMetadata,
            password: password,
            secretHash: secretHash(username: username),
            userAttributes: userAttributes,
            username: username
        )
        do {
            return try await self.configuration.cognitoIDP.signUp(request, logger: logger)
        } catch {
            throw self.translateError(error: error)
        }
    }

    /// Confirm sign up of user
    ///
    /// If user was created through signUp and they were sent an email containing a confirmation code the creation of the user can be confirm using this function along with the confirmation code
    /// - parameters:
    ///     - username: user name for user
    ///     - confirmationCode: Confirmation code in email
    ///     - clientMetadata: A map of custom key-value pairs that you can provide as input for AWS Lambda custom workflows
    ///     - logger: logger
    public func confirmSignUp(
        username: String,
        confirmationCode: String,
        clientMetadata: [String: String]? = nil,
        logger: Logger = AWSClient.loggingDisabled
    ) async throws {
        let request = CognitoIdentityProvider.ConfirmSignUpRequest(
            clientId: self.configuration.clientId,
            clientMetadata: clientMetadata,
            confirmationCode: confirmationCode,
            forceAliasCreation: false,
            secretHash: secretHash(username: username),
            username: username
        )
        do {
            _ = try await self.configuration.cognitoIDP.confirmSignUp(request, logger: logger)
        } catch {
            throw self.translateError(error: error)
        }
    }

    /// create a new AWS Cognito user.
    ///
    /// This uses AdminCreateUser. An invitation email, with a password  is sent to the user. This password requires to be renewed as soon as it is used. As this function uses an Admin
    /// function it requires an `adminClient`.
    /// - parameters:
    ///     - username: user name for new user
    ///     - attributes: user attributes. These should be from the list of standard claims detailed in the [OpenID spec](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims) .
    ///         You can include custom attributes by prepending them with "custom:".
    ///     - temporaryPassword: Temporary password to give user
    ///     - messageAction: If this is set to `.resend` this will resend the message for an existing user. If this is set to `.suppress` the message sending is suppressed.
    ///     - clientMetadata: A map of custom key-value pairs that you can provide as input for AWS Lambda custom workflows
    ///     - logger: logger
    /// - returns:
    ///     Create user response
    public func createUser(
        username: String,
        attributes: [String: String],
        temporaryPassword: String? = nil,
        messageAction: CognitoIdentityProvider.MessageActionType? = nil,
        clientMetadata: [String: String]? = nil,
        logger: Logger = AWSClient.loggingDisabled
    ) async throws -> CognitoCreateUserResponse {
        guard self.configuration.adminClient == true else {
            throw SotoCognitoError.unauthorized(reason: "\(#function) requires an admin client with authenticated AWSClient")
        }
        let userAttributes = attributes.map { return CognitoIdentityProvider.AttributeType(name: $0.key, value: $0.value) }
        let request = CognitoIdentityProvider.AdminCreateUserRequest(
            clientMetadata: clientMetadata,
            desiredDeliveryMediums: [.email],
            messageAction: messageAction,
            temporaryPassword: temporaryPassword,
            userAttributes: userAttributes,
            username: username,
            userPoolId: self.configuration.userPoolId
        )
        do {
            let response = try await self.configuration.cognitoIDP.adminCreateUser(
                request,
                logger: logger
            )
            guard let user = response.user,
                  let username = user.username,
                  let userStatus = user.userStatus
            else { throw SotoCognitoError.unexpectedResult(reason: "AWS did not supply all the user information expected") }
            return CognitoCreateUserResponse(userName: username, userStatus: userStatus)
        } catch {
            throw self.translateError(error: error)
        }
    }

    /// Authenticate using a username and password.
    ///
    /// This function combines the `initiateAuth`` and `respondToAuthChallenge` calls. If the initiateAuth returns
    /// a challenge then the provided closure `respondToChallenge` is called. You should return a challenge response
    /// from this call, or if you do not know how to respond then return `nil`.
    ///
    /// - parameters:
    ///     - username: user name for user
    ///     - password: password for user
    ///     - clientMetadata: A map of custom key-value pairs that you can provide as input for AWS Lambda custom workflows
    ///     - context: Context data for this request
    ///     - respondToChallenge: Function which returns challenge response parameters given a challenge, or the last
    ///         challenge and the error it generated
    ///     - maxChallengeResponseAttempts: Maximum number of times we are allowed to respond to challenges
    ///     - logger: logger
    /// - returns:
    ///     An authentication response. This can contain a challenge which the user has to fulfill before being allowed to login, or authentication access, id and refresh keys
    public func authenticate(
        username: String,
        password: String,
        clientMetadata: [String: String]? = nil,
        context: CognitoContextData? = nil,
        respondToChallenge: @escaping @Sendable (CognitoChallengeName, [String: String]?, Error?) async throws -> [String: String]?,
        maxChallengeResponseAttempts: Int = 4,
        logger: Logger = AWSClient.loggingDisabled
    ) async throws -> CognitoAuthenticateResponse.AuthenticatedResponse {
        let authFlow: CognitoIdentityProvider.AuthFlowType = self.configuration.adminClient ? .adminUserPasswordAuth : .userPasswordAuth
        var authParameters: [String: String] = [
            "USERNAME": username,
            "PASSWORD": password,
        ]
        authParameters["SECRET_HASH"] = secretHash(username: username)
        return try await self.authRequest(
            username: username,
            authFlow: authFlow,
            authParameters: authParameters,
            clientMetadata: clientMetadata,
            context: context,
            respondToChallenge: respondToChallenge,
            maxChallengeResponseAttempts: maxChallengeResponseAttempts,
            logger: logger
        )
    }

    /// Get new access and id tokens from a refresh token
    ///
    /// The username you provide here has to be the real username of the user not an alias like an email. You can get
    /// the real username by authenticing an access token.
    ///
    /// This function combines the `initiateAuth`` and `respondToAuthChallenge` calls. If the initiateAuth returns
    /// a challenge then the provided closure `respondToChallenge` is called. You should return a challenge response
    /// from this call, or if you do not know how to respond then return `nil`.
    ///
    /// - parameters:
    ///     - username: user name of user
    ///     - refreshToken: refresh token required to generate new access and id tokens
    ///     - clientMetadata: A map of custom key-value pairs that you can provide as input for AWS Lambda custom workflows
    ///     - context: Context data for this request
    ///     - respondToChallenge: Function which returns challenge response parameters given a challenge, or the last
    ///         challenge and the error it generated
    ///     - maxChallengeResponseAttempts: Maximum number of times we are allowed to respond to challenges
    ///     - logger: logger
    /// - returns:
    ///     - An authentication result which should include an id and status token
    public func refresh(
        username: String,
        refreshToken: String,
        clientMetadata: [String: String]? = nil,
        context: CognitoContextData? = nil,
        respondToChallenge: @escaping @Sendable (CognitoChallengeName, [String: String]?, Error?) async throws -> [String: String]?,
        maxChallengeResponseAttempts: Int = 4,
        logger: Logger = AWSClient.loggingDisabled
    ) async throws -> CognitoAuthenticateResponse.AuthenticatedResponse {
        var authParameters: [String: String] = [
            "USERNAME": username,
            "REFRESH_TOKEN": refreshToken,
        ]
        authParameters["SECRET_HASH"] = secretHash(username: username)

        return try await self.authRequest(
            username: username,
            authFlow: .refreshTokenAuth,
            authParameters: authParameters,
            clientMetadata: clientMetadata,
            context: context,
            respondToChallenge: respondToChallenge,
            maxChallengeResponseAttempts: maxChallengeResponseAttempts,
            logger: logger
        )
    }

    /// Authenticate using a username and password.
    /// This function uses the Admin version of the initiateAuthRequest so your CognitoIdentityProvider should be setup with AWS credentials.
    ///
    /// - parameters:
    ///     - username: user name for user
    ///     - password: password for user
    ///     - clientMetadata: A map of custom key-value pairs that you can provide as input for AWS Lambda custom workflows
    ///     - context: Context data for this request
    ///     - logger: logger
    /// - returns:
    ///     An authentication response. This can contain a challenge which the user has to fulfill before being allowed to login, or authentication access, id and refresh keys
    public func authenticate(
        username: String,
        password: String,
        clientMetadata: [String: String]? = nil,
        context: CognitoContextData? = nil,
        logger: Logger = AWSClient.loggingDisabled
    ) async throws -> CognitoAuthenticateResponse {
        let authFlow: CognitoIdentityProvider.AuthFlowType = self.configuration.adminClient ? .adminUserPasswordAuth : .userPasswordAuth
        var authParameters: [String: String] = [
            "USERNAME": username,
            "PASSWORD": password,
        ]
        authParameters["SECRET_HASH"] = secretHash(username: username)
        return try await self.initiateAuthRequest(
            authFlow: authFlow,
            authParameters: authParameters,
            clientMetadata: clientMetadata,
            context: context,
            logger: logger
        )
    }

    /// Get new access and id tokens from a refresh token
    ///
    /// The username you provide here has to be the real username of the user not an alias like an email. You can get the real username by authenticing an access token
    /// - parameters:
    ///     - username: user name of user
    ///     - refreshToken: refresh token required to generate new access and id tokens
    ///     - clientMetadata: A map of custom key-value pairs that you can provide as input for AWS Lambda custom workflows
    ///     - context: Context data for this request
    ///     - logger: logger
    /// - returns:
    ///     - An authentication result which should include an id and status token
    public func refresh(
        username: String,
        refreshToken: String,
        clientMetadata: [String: String]? = nil,
        context: CognitoContextData? = nil,
        logger: Logger = AWSClient.loggingDisabled
    ) async throws -> CognitoAuthenticateResponse {
        var authParameters: [String: String] = [
            "USERNAME": username,
            "REFRESH_TOKEN": refreshToken,
        ]
        authParameters["SECRET_HASH"] = secretHash(username: username)

        return try await self.initiateAuthRequest(
            authFlow: .refreshTokenAuth,
            authParameters: authParameters,
            clientMetadata: clientMetadata,
            context: context,
            logger: logger
        )
    }

    /// respond to authentication challenge
    ///
    /// In some situations when logging in Cognito will respond with a challenge before you are allowed to login. These could be supplying a new password for a new account,
    /// supply an MFA code. This is used to respond to those challenges. You respond with the challenge name, the session id return in the challenge and the response values required.
    /// If successful you will be returned an authenticated response which includes the access, id and refresh tokens.
    ///
    /// - parameters:
    ///     - username: User name of user
    ///     - name: Name of challenge
    ///     - responses: Challenge responses
    ///     - session: Session id returned with challenge
    ///     - clientMetadata: A map of custom key-value pairs that you can provide as input for AWS Lambda custom workflows
    ///     - context: Context data for this request
    ///     - logger: logger
    /// - returns:
    ///     An authentication response. This can contain another challenge which the user has to fulfill before being allowed to login, or authentication access, id and refresh keys
    public func respondToChallenge(
        username: String,
        name: CognitoChallengeName,
        responses: [String: String],
        session: String?,
        clientMetadata: [String: String]? = nil,
        context: CognitoContextData? = nil,
        logger: Logger = AWSClient.loggingDisabled
    ) async throws -> CognitoAuthenticateResponse {
        var challengeResponses = responses
        challengeResponses["USERNAME"] = username
        challengeResponses["SECRET_HASH"] = secretHash(username: username)

        do {
            let response: CognitoIdentityProvider.AdminRespondToAuthChallengeResponse
            // If authentication required that use admin version of RespondToAuthChallenge
            if self.configuration.adminClient {
                let context = context?.contextData
                let request = CognitoIdentityProvider.AdminRespondToAuthChallengeRequest(
                    challengeName: name,
                    challengeResponses: challengeResponses,
                    clientId: self.configuration.clientId,
                    clientMetadata: clientMetadata,
                    contextData: context,
                    session: session,
                    userPoolId: self.configuration.userPoolId
                )
                response = try await self.configuration.cognitoIDP.adminRespondToAuthChallenge(request, logger: logger)
            } else {
                let request = CognitoIdentityProvider.RespondToAuthChallengeRequest(
                    challengeName: name,
                    challengeResponses: challengeResponses,
                    clientId: self.configuration.clientId,
                    clientMetadata: clientMetadata,
                    session: session
                )
                let challengeResponse = try await self.configuration.cognitoIDP.respondToAuthChallenge(
                    request,
                    logger: logger
                )
                response = CognitoIdentityProvider.AdminRespondToAuthChallengeResponse(
                    authenticationResult: challengeResponse.authenticationResult,
                    challengeName: challengeResponse.challengeName,
                    challengeParameters: challengeResponse.challengeParameters,
                    session: challengeResponse.session
                )
            }
            guard let authenticationResult = response.authenticationResult,
                  let accessToken = authenticationResult.accessToken,
                  let idToken = authenticationResult.idToken
            else {
                // if there was no tokens returned, return challenge if it exists
                if let challengeName = response.challengeName {
                    return .challenged(.init(
                        name: challengeName,
                        parameters: response.challengeParameters,
                        session: response.session
                    )
                    )
                }
                throw SotoCognitoError.unexpectedResult(reason: "Authenticated response is not authentication tokens or challenge information") // should have either an authenticated result or a challenge
            }
            return .authenticated(.init(
                accessToken: accessToken,
                idToken: idToken,
                refreshToken: authenticationResult.refreshToken,
                expiresIn: authenticationResult.expiresIn != nil ? Date(timeIntervalSinceNow: TimeInterval(authenticationResult.expiresIn!)) : nil
            ))
        } catch {
            throw self.translateError(error: error)
        }
    }

    /// respond to new password authentication challenge
    ///
    /// - parameters:
    ///     - username: User name of user
    ///     - password: new password
    ///     - session: Session id returned with challenge
    ///     - context: Context data for this request
    ///     - logger: logger
    /// - returns:
    ///     An authentication response. This can contain another challenge which the user has to fulfill before being allowed to login, or authentication access, id and refresh keys
    public func respondToNewPasswordChallenge(
        username: String,
        password: String,
        session: String?,
        context: CognitoContextData? = nil,
        logger: Logger = AWSClient.loggingDisabled
    ) async throws -> CognitoAuthenticateResponse {
        return try await self.respondToChallenge(
            username: username,
            name: .newPasswordRequired,
            responses: ["NEW_PASSWORD": password],
            session: session,
            context: context,
            logger: logger
        )
    }

    /// respond to MFA token challenge
    ///
    /// - parameters:
    ///     - username: User name of user
    ///     - password: new password
    ///     - session: Session id returned with challenge
    ///     - context: Context data for this request
    ///     - logger: logger
    /// - returns:
    ///     An authentication response. This can contain another challenge which the user has to fulfill before being allowed to login, or authentication access, id and refresh keys
    public func respondToMFAChallenge(
        username: String,
        token: String,
        session: String?,
        context: CognitoContextData? = nil,
        logger: Logger = AWSClient.loggingDisabled
    ) async throws -> CognitoAuthenticateResponse {
        return try await self.respondToChallenge(
            username: username,
            name: .smsMfa,
            responses: ["SMS_MFA_CODE": token],
            session: session,
            context: context,
            logger: logger
        )
    }

    /// update the users attributes. This requires an `adminClient`
    /// - parameters:
    ///     - username: user name of user
    ///     - attributes: list of updated attributes for user
    ///     - logger: logger
    public func updateUserAttributes(
        username: String,
        attributes: [String: String],
        logger: Logger = AWSClient.loggingDisabled
    ) async throws {
        guard self.configuration.adminClient == true else {
            throw SotoCognitoError.unauthorized(reason: "\(#function) requires an admin client with authenticated AWSClient")
        }
        let attributes = attributes.map { CognitoIdentityProvider.AttributeType(name: $0.key, value: $0.value) }
        let request = CognitoIdentityProvider.AdminUpdateUserAttributesRequest(userAttributes: attributes, username: username, userPoolId: self.configuration.userPoolId)
        do {
            _ = try await self.configuration.cognitoIDP.adminUpdateUserAttributes(request, logger: logger)
        } catch {
            throw self.translateError(error: error)
        }
    }

    /// update the users attributes, given an access token
    /// - parameters:
    ///     - accessToken: user name of user
    ///     - attributes: list of updated attributes for user
    ///     - logger: logger
    public func updateUserAttributes(
        accessToken: String,
        attributes: [String: String],
        clientMetadata: [String: String]? = nil,
        logger: Logger = AWSClient.loggingDisabled
    ) async throws {
        let attributes = attributes.map { CognitoIdentityProvider.AttributeType(name: $0.key, value: $0.value) }
        let request = CognitoIdentityProvider.UpdateUserAttributesRequest(accessToken: accessToken, clientMetadata: clientMetadata, userAttributes: attributes)
        do {
            _ = try await self.configuration.cognitoIDP.updateUserAttributes(request, logger: logger)
        } catch {
            throw self.translateError(error: error)
        }
    }

    /// Start forgot password flow. An email/sms will be sent to the user with a reset code
    /// - Parameters:
    ///     - username: user name of user
    ///     - clientMetadata: A map of custom key-value pairs that you can provide as input for AWS Lambda custom workflows
    ///     - logger: logger
    public func forgotPassword(
        username: String,
        clientMetadata: [String: String]? = nil,
        logger: Logger = AWSClient.loggingDisabled
    ) async throws {
        let request = CognitoIdentityProvider.ForgotPasswordRequest(
            clientId: self.configuration.clientId,
            clientMetadata: clientMetadata,
            secretHash: self.secretHash(username: username),
            username: username
        )
        _ = try await self.configuration.cognitoIDP.forgotPassword(request, logger: logger)
    }

    /// Confirm new password in forgot password flow
    /// - Parameters:
    ///     - username: user name of user
    ///     - newPassword: new password
    ///     - confirmationCode: confirmation code sent to user
    ///     - clientMetadata: A map of custom key-value pairs that you can provide as input for AWS Lambda custom workflows
    ///     - logger: logger
    public func confirmForgotPassword(
        username: String,
        newPassword: String,
        confirmationCode: String,
        clientMetadata: [String: String]? = nil,
        logger: Logger = AWSClient.loggingDisabled
    ) async throws {
        let request = CognitoIdentityProvider.ConfirmForgotPasswordRequest(
            clientId: self.configuration.clientId,
            clientMetadata: clientMetadata,
            confirmationCode: confirmationCode,
            password: newPassword,
            secretHash: self.secretHash(username: username),
            username: username
        )
        _ = try await self.configuration.cognitoIDP.confirmForgotPassword(request, logger: logger)
    }
}

extension CognitoAuthenticatable {
    public func authRequest(
        username: String,
        authFlow: CognitoIdentityProvider.AuthFlowType,
        authParameters: [String: String],
        clientMetadata: [String: String]? = nil,
        context: CognitoContextData?,
        respondToChallenge: @escaping @Sendable (CognitoChallengeName, [String: String]?, Error?) async throws -> [String: String]? = { _, _, _ in nil },
        maxChallengeResponseAttempts: Int = 4,
        logger: Logger
    ) async throws -> CognitoAuthenticateResponse.AuthenticatedResponse {
        var authResponse = try await self.initiateAuthRequest(authFlow: authFlow, authParameters: authParameters, clientMetadata: clientMetadata, context: context, logger: logger)
        var prevError: CognitoIdentityProviderErrorType? = nil
        var challengeResponseAttempts = 0
        while true {
            switch authResponse {
            case .authenticated(let authenticated):
                return authenticated
            case .challenged(let challenge):
                guard let challengeName = challenge.name else {
                    throw SotoCognitoError.unexpectedResult(reason: "Challenge response does not have valid challenge name")
                }
                guard challengeResponseAttempts < maxChallengeResponseAttempts else {
                    if let error = prevError {
                        throw error
                    } else {
                        throw SotoCognitoError.unauthorized(reason: "Failed to produce valid response to challenge \(challengeName)")
                    }
                }
                challengeResponseAttempts += 1
                let parameters = try await respondToChallenge(challengeName, challenge.parameters, prevError)
                guard let parameters else {
                    throw SotoCognitoError.unauthorized(reason: "Did not respond to challenge \(challengeName)")
                }
                do {
                    authResponse = try await self.respondToChallenge(
                        username: username,
                        name: challengeName,
                        responses: parameters,
                        session: challenge.session,
                        clientMetadata: clientMetadata,
                        context: context,
                        logger: logger
                    )
                } catch let error as CognitoIdentityProviderErrorType {
                    prevError = error
                }
            }
        }
    }

    /// Return an authorization request future. This is an internal function and shouldn't need to be called
    public func initiateAuthRequest(
        authFlow: CognitoIdentityProvider.AuthFlowType,
        authParameters: [String: String],
        clientMetadata: [String: String]? = nil,
        context: CognitoContextData?,
        logger: Logger
    ) async throws -> CognitoAuthenticateResponse {
        do {
            let initAuthResponse: CognitoIdentityProvider.AdminInitiateAuthResponse
            if self.configuration.adminClient {
                let context = context?.contextData
                let request = CognitoIdentityProvider.AdminInitiateAuthRequest(
                    authFlow: authFlow,
                    authParameters: authParameters,
                    clientId: self.configuration.clientId,
                    clientMetadata: clientMetadata,
                    contextData: context,
                    userPoolId: self.configuration.userPoolId
                )
                initAuthResponse = try await self.configuration.cognitoIDP.adminInitiateAuth(request, logger: logger)
            } else {
                let request = CognitoIdentityProvider.InitiateAuthRequest(
                    authFlow: authFlow,
                    authParameters: authParameters,
                    clientId: self.configuration.clientId,
                    clientMetadata: clientMetadata
                )
                let response = try await self.configuration.cognitoIDP.initiateAuth(
                    request,
                    logger: logger
                )
                initAuthResponse = CognitoIdentityProvider.AdminInitiateAuthResponse(
                    authenticationResult: response.authenticationResult,
                    challengeName: response.challengeName,
                    challengeParameters: response.challengeParameters,
                    session: response.session
                )
            }
            guard let authenticationResult = initAuthResponse.authenticationResult,
                  let accessToken = authenticationResult.accessToken,
                  let idToken = authenticationResult.idToken
            else {
                // if there was no tokens returned, return challenge if it exists
                if let challengeName = initAuthResponse.challengeName {
                    return .challenged(.init(
                        name: challengeName,
                        parameters: initAuthResponse.challengeParameters,
                        session: initAuthResponse.session
                    ))
                }
                throw SotoCognitoError.unexpectedResult(reason: "Authenticated response does not authentication tokens or challenge information") // should have either an authenticated result or a challenge
            }

            return .authenticated(.init(
                accessToken: accessToken,
                idToken: idToken,
                refreshToken: authenticationResult.refreshToken,
                expiresIn: authenticationResult.expiresIn != nil ? Date(timeIntervalSinceNow: TimeInterval(authenticationResult.expiresIn!)) : nil
            ))
        } catch {
            throw self.translateError(error: error)
        }
    }
}

extension CognitoAuthenticatable {
    /// Return secret hash to include in cognito identity provider calls. This is an internal function and shouldn't need to be called
    public func secretHash(username: String) -> String? {
        guard let clientSecret = configuration.clientSecret else { return nil }
        let message = username + self.configuration.clientId
        let messageHmac: HashedAuthenticationCode<SHA256> = HMAC.authenticationCode(for: Data(message.utf8), using: SymmetricKey(data: Data(clientSecret.utf8)))
        return Data(messageHmac).base64EncodedString()
    }

    /// Translate error from one thrown by Soto. This is an internal function and shouldn't need to be called
    public func translateError(error: Error) -> Error {
        switch error {
        case let error as CognitoIdentityProviderErrorType where error == .notAuthorizedException:
            return SotoCognitoError.unauthorized(reason: error.message)
        case let error as AWSClientError where error == .missingAuthenticationToken:
            return SotoCognitoError.unauthorized(reason: error.message)
        default:
            return error
        }
    }
}

// jwtSigners is mutable but access is controlled by a lock so required to use @unchecked here.
extension CognitoAuthenticatable: @unchecked Sendable {}
