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

import Crypto
import Foundation
import JWTKit
import NIO
@_exported import SotoCognitoIdentityProvider

/// Public interface functions for authenticating with CognitoIdentityProvider and generating access and id tokens.
@available(macOS 12.0, iOS 15.0, watchOS 8.0, tvOS 15.0, *)
extension CognitoAuthenticatable {
    // MARK: Async/Await Methods

    /// Sign up as AWS Cognito user.
    ///
    /// An email will be sent out with either a confirmation code or a link to confirm the user.
    /// - parameters:
    ///     - username: user name for new user
    ///     - attributes: user attributes. These should be from the list of standard claims detailed in the [OpenID spec](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims). You can include custom attiibutes by prepending them with "custom:".
    ///     - clientMetadata: A map of custom key-value pairs that you can provide as input for AWS Lambda custom workflows
    ///     - on: Event loop request is running on.
    /// - returns:
    ///     Sign up response
    public func signUp(
        username: String,
        password: String,
        attributes: [String: String],
        clientMetadata: [String: String]? = nil,
        on eventLoop: EventLoop? = nil
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
            return try await self.configuration.cognitoIDP.signUp(request, on: eventLoop)
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
    ///     - on: Event loop request is running on.
    public func confirmSignUp(
        username: String,
        confirmationCode: String,
        clientMetadata: [String: String]? = nil,
        on eventLoop: EventLoop? = nil
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
            _ = try await self.configuration.cognitoIDP.confirmSignUp(request, on: eventLoop)
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
    ///     - attributes: user attributes. These should be from the list of standard claims detailed in the [OpenID spec](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims) . You can include custom attiibutes by prepending them with "custom:".
    ///     - messageAction: If this is set to `.resend` this will resend the message for an existing user. If this is set to `.suppress` the message sending is suppressed.
    ///     - clientMetadata: A map of custom key-value pairs that you can provide as input for AWS Lambda custom workflows
    ///     - on: Event loop request is running on.
    /// - returns:
    ///     Create user response
    public func createUser(
        username: String,
        attributes: [String: String],
        temporaryPassword: String? = nil,
        messageAction: CognitoIdentityProvider.MessageActionType? = nil,
        clientMetadata: [String: String]? = nil,
        on eventLoop: EventLoop? = nil
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
            let response = try await self.configuration.cognitoIDP.adminCreateUser(request, on: eventLoop)
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
    /// This function uses the Admin version of the initiateAuthRequest so your CognitoIdentityProvider should be setup with AWS credentials.
    ///
    /// - parameters:
    ///     - username: user name for user
    ///     - password: password for user
    ///     - clientMetadata: A map of custom key-value pairs that you can provide as input for AWS Lambda custom workflows
    ///     - context: Context data for this request
    ///     - on: Eventloop request should run on.
    /// - returns:
    ///     An authentication response. This can contain a challenge which the user has to fulfill before being allowed to login, or authentication access, id and refresh keys
    public func authenticate(
        username: String,
        password: String,
        clientMetadata: [String: String]? = nil,
        context: CognitoContextData? = nil,
        on eventLoop: EventLoop? = nil
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
            on: eventLoop
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
    ///     - on: Eventloop request should run on.
    /// - returns:
    ///     - An authentication result which should include an id and status token
    public func refresh(
        username: String,
        refreshToken: String,
        clientMetadata: [String: String]? = nil,
        context: CognitoContextData? = nil,
        on eventLoop: EventLoop? = nil
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
            on: eventLoop
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
    ///     - on: Eventloop request should run on.
    /// - returns:
    ///     An authentication response. This can contain another challenge which the user has to fulfill before being allowed to login, or authentication access, id and refresh keys
    public func respondToChallenge(
        username: String,
        name: CognitoChallengeName,
        responses: [String: String],
        session: String?,
        clientMetadata: [String: String]? = nil,
        context: CognitoContextData? = nil,
        on eventLoop: EventLoop? = nil
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
                response = try await self.configuration.cognitoIDP.adminRespondToAuthChallenge(request, on: eventLoop)
            } else {
                let request = CognitoIdentityProvider.RespondToAuthChallengeRequest(
                    challengeName: name,
                    challengeResponses: challengeResponses,
                    clientId: self.configuration.clientId,
                    clientMetadata: clientMetadata,
                    session: session
                )
                let challengeResponse = try await self.configuration.cognitoIDP.respondToAuthChallenge(request, on: eventLoop)
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
                        name: challengeName.rawValue,
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
    ///     - on: Eventloop request should run on.
    /// - returns:
    ///     An authentication response. This can contain another challenge which the user has to fulfill before being allowed to login, or authentication access, id and refresh keys
    public func respondToNewPasswordChallenge(
        username: String,
        password: String,
        session: String?,
        context: CognitoContextData? = nil,
        on eventLoop: EventLoop? = nil
    ) async throws -> CognitoAuthenticateResponse {
        return try await self.respondToChallenge(
            username: username,
            name: .newPasswordRequired,
            responses: ["NEW_PASSWORD": password],
            session: session,
            context: context,
            on: eventLoop
        )
    }

    /// respond to MFA token challenge
    ///
    /// - parameters:
    ///     - username: User name of user
    ///     - password: new password
    ///     - session: Session id returned with challenge
    ///     - context: Context data for this request
    ///     - on: Eventloop request should run on.
    /// - returns:
    ///     An authentication response. This can contain another challenge which the user has to fulfill before being allowed to login, or authentication access, id and refresh keys
    public func respondToMFAChallenge(
        username: String,
        token: String,
        session: String?,
        context: CognitoContextData? = nil,
        on eventLoop: EventLoop? = nil
    ) async throws -> CognitoAuthenticateResponse {
        return try await self.respondToChallenge(
            username: username,
            name: .smsMfa,
            responses: ["SMS_MFA_CODE": token],
            session: session,
            context: context,
            on: eventLoop
        )
    }

    /// update the users attributes. This requires an `adminClient`
    /// - parameters:
    ///     - username: user name of user
    ///     - attributes: list of updated attributes for user
    ///     - on: Event loop request is running on.
    public func updateUserAttributes(
        username: String,
        attributes: [String: String],
        on eventLoop: EventLoop? = nil
    ) async throws {
        guard self.configuration.adminClient == true else {
            throw SotoCognitoError.unauthorized(reason: "\(#function) requires an admin client with authenticated AWSClient")
        }
        let attributes = attributes.map { CognitoIdentityProvider.AttributeType(name: $0.key, value: $0.value) }
        let request = CognitoIdentityProvider.AdminUpdateUserAttributesRequest(userAttributes: attributes, username: username, userPoolId: self.configuration.userPoolId)
        do {
            _ = try await self.configuration.cognitoIDP.adminUpdateUserAttributes(request, on: eventLoop)
        } catch {
            throw self.translateError(error: error)
        }
    }

    /// update the users attributes, given an access token
    /// - parameters:
    ///     - accessToken: user name of user
    ///     - attributes: list of updated attributes for user
    ///     - on: Event loop request is running on.
    public func updateUserAttributes(
        accessToken: String,
        attributes: [String: String],
        clientMetadata: [String: String]? = nil,
        on eventLoop: EventLoop? = nil
    ) async throws {
        let attributes = attributes.map { CognitoIdentityProvider.AttributeType(name: $0.key, value: $0.value) }
        let request = CognitoIdentityProvider.UpdateUserAttributesRequest(accessToken: accessToken, clientMetadata: clientMetadata, userAttributes: attributes)
        do {
            _ = try await self.configuration.cognitoIDP.updateUserAttributes(request, on: eventLoop)
        } catch {
            throw self.translateError(error: error)
        }
    }

    /// Start forgot password flow. An email/sms will be sent to the user with a reset code
    /// - Parameters:
    ///   - username: user name of user
    ///   - clientMetadata: A map of custom key-value pairs that you can provide as input for AWS Lambda custom workflows
    ///   - eventLoop: Event loop request is running on.
    public func forgotPassword(
        username: String,
        clientMetadata: [String: String]? = nil,
        on eventLoop: EventLoop? = nil
    ) async throws {
        let request = CognitoIdentityProvider.ForgotPasswordRequest(
            clientId: self.configuration.clientId,
            clientMetadata: clientMetadata,
            secretHash: self.secretHash(username: username),
            username: username
        )
        _ = try await self.configuration.cognitoIDP.forgotPassword(request, on: eventLoop)
    }

    /// Confirm new password in forgot password flow
    /// - Parameters:
    ///   - username: user name of user
    ///   - newPassword: new password
    ///   - confirmationCode: confirmation code sent to user
    ///   - clientMetadata: A map of custom key-value pairs that you can provide as input for AWS Lambda custom workflows
    ///   - eventLoop: Event loop request is running on.
    public func confirmForgotPassword(
        username: String,
        newPassword: String,
        confirmationCode: String,
        clientMetadata: [String: String]? = nil,
        on eventLoop: EventLoop? = nil
    ) async throws {
        let request = CognitoIdentityProvider.ConfirmForgotPasswordRequest(
            clientId: self.configuration.clientId,
            clientMetadata: clientMetadata,
            confirmationCode: confirmationCode,
            password: newPassword,
            secretHash: self.secretHash(username: username),
            username: username
        )
        _ = try await self.configuration.cognitoIDP.confirmForgotPassword(request, on: eventLoop)
    }
}

@available(macOS 12.0, iOS 15.0, watchOS 8.0, tvOS 15.0, *)
public extension CognitoAuthenticatable {
    /// Return an authorization request future. This is an internal function and shouldn't need to be called
    func initiateAuthRequest(
        authFlow: CognitoIdentityProvider.AuthFlowType,
        authParameters: [String: String],
        clientMetadata: [String: String]? = nil,
        context: CognitoContextData?,
        on eventLoop: EventLoop?
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
                initAuthResponse = try await self.configuration.cognitoIDP.adminInitiateAuth(request, on: eventLoop)
            } else {
                let request = CognitoIdentityProvider.InitiateAuthRequest(
                    authFlow: authFlow,
                    authParameters: authParameters,
                    clientId: self.configuration.clientId,
                    clientMetadata: clientMetadata
                )
                let response = try await self.configuration.cognitoIDP.initiateAuth(request, on: eventLoop)
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
                        name: challengeName.rawValue,
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

#endif // compiler(>=5.5) && canImport(_Concurrency)
