@_exported import CognitoIdentityProvider
@_exported import JWTKit

import AWSSDKSwiftCore
import Foundation
import NIO
import OpenCrypto

public typealias AWSCognitoChallengeName = CognitoIdentityProvider.ChallengeNameType
public typealias AWSCognitoUserStatusType = CognitoIdentityProvider.UserStatusType

public enum AWSCognitoError: Error {
    case failedToCreateContextData
    case unexpectedResult(reason: String?)
    case unauthorized(reason: String?)
    case invalidPublicKey
}

/// Response to create user
public struct AWSCognitoCreateUserResponse {
    public var userName: String
    public var userStatus: AWSCognitoUserStatusType
}

/// Response to initAuth
public struct AWSCognitoAuthenticateResponse {

    public struct AuthenticatedResponse {
        public let accessToken : String?
        public let idToken : String?
        public let refreshToken : String?
        public let expiresIn: Date?
    }

    public struct ChallengedResponse {
        public let name: String?
        public let parameters: [String: String]?
        public let session: String?
    }

    public let authenticated: AuthenticatedResponse?
    public let challenged: ChallengedResponse?

    init(authenticated: AuthenticatedResponse? = nil, challenged: ChallengedResponse? = nil) {
        self.authenticated = authenticated
        self.challenged = challenged
    }
}


/// Public interface functions for authenticating with CognitoIdentityProvider and generating access and id tokens.
public class AWSCognitoAuthenticatable {

    /// configuration
    public let configuration: AWSCognitoConfiguration
    /// JWT SIgners
    var jwtSigners: JWTSigners?
    
    public init(configuration: AWSCognitoConfiguration) {
        self.configuration = configuration
        self.jwtSigners = nil
    }
    
    /// Sign up as AWS Cognito user.
    ///
    /// An email will be sent out with either a confirmation code or a link to confirm the user.
    /// - parameters:
    ///     - username: user name for new user
    ///     - attributes: user attributes. These should be from the list of standard claims detailed in the [OpenID spec](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims). You can include custom attiibutes by prepending them with "custom:".
    ///     - on: Event loop request is running on.
    /// - returns:
    ///     EventLoopFuture holding the sign up response
    public func signUp(username: String, password: String, attributes: [String:String], on eventLoop: EventLoop) -> EventLoopFuture<CognitoIdentityProvider.SignUpResponse> {
        return secretHashFuture(username: username, on: eventLoop).flatMap { secretHash in
            let userAttributes = attributes.map { return CognitoIdentityProvider.AttributeType(name: $0.key, value: $0.value) }
            let request = CognitoIdentityProvider.SignUpRequest(clientId: self.configuration.clientId, password: password, secretHash: secretHash, userAttributes: userAttributes, username: username)
            return self.configuration.cognitoIDP.signUp(request)
                .flatMapErrorThrowing { error in
                    throw self.translateError(error: error)
                }
                .hop(to: eventLoop)
        }
    }

    /// Confirm sign up of user
    ///
    /// If user was created through signUp and they were sent an email containing a confirmation code the creation of the user can be confirm using this function along with the confirmation code
    /// - parameters:
    ///     - username: user name for user
    ///     - confirmationCode: Confirmation code in email
    ///     - on: Event loop request is running on.
    /// - returns:
    ///     Empty EventLoopFuture
    public func confirmSignUp(username: String, confirmationCode: String, on eventLoop: EventLoop) -> EventLoopFuture<Void> {
        return secretHashFuture(username: username, on: eventLoop).flatMap { secretHash in
            let request = CognitoIdentityProvider.ConfirmSignUpRequest(clientId: self.configuration.clientId, confirmationCode: confirmationCode, forceAliasCreation: false, secretHash: secretHash, username: username)
            return self.configuration.cognitoIDP.confirmSignUp(request)
                .flatMapErrorThrowing { error in
                    throw self.translateError(error: error)
                }
                .map { _ in
                    return
            }
            .hop(to: eventLoop)
        }
    }

    /// create a new AWS Cognito user.
    ///
    /// This uses AdminCreateUser. An invitation email, with a password  is sent to the user. This password requires to be renewed as soon as it is used.
    /// - parameters:
    ///     - username: user name for new user
    ///     - attributes: user attributes. These should be from the list of standard claims detailed in the [OpenID spec](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims) . You can include custom attiibutes by prepending them with "custom:".
    ///     - messageAction: If this is set to `.resend` this will resend the message for an existing user. If this is set to `.suppress` the message sending is suppressed.
    ///     - on: Event loop request is running on.
    /// - returns:
    ///     EventLoopFuture holding the create user response
    public func createUser(username: String, attributes: [String:String], temporaryPassword: String? = nil, messageAction: CognitoIdentityProvider.MessageActionType? = nil, on eventLoop: EventLoop) -> EventLoopFuture<AWSCognitoCreateUserResponse> {
        let userAttributes = attributes.map { return CognitoIdentityProvider.AttributeType(name: $0.key, value: $0.value) }
        let request = CognitoIdentityProvider.AdminCreateUserRequest(desiredDeliveryMediums:[.email], messageAction: messageAction, temporaryPassword: temporaryPassword, userAttributes: userAttributes, username: username, userPoolId: configuration.userPoolId)
        return configuration.cognitoIDP.adminCreateUser(request)
            .flatMapErrorThrowing { error in
                throw self.translateError(error: error)
            }
            .flatMapThrowing { response in
                guard let user = response.user,
                    let username = user.username,
                    let userStatus = user.userStatus
                    else { throw AWSCognitoError.unexpectedResult(reason: "AWS did not supply all the user information expected") }
                return AWSCognitoCreateUserResponse(userName: username, userStatus: userStatus)
        }
        .hop(to: eventLoop)
    }

    /// authenticate using a username and password
    ///
    /// - parameters:
    ///     - username: user name for user
    ///     - password: password for user
    ///     - with: Eventloop and authenticate context. You can use a Vapor request here.
    /// - returns:
    ///     An authentication response. This can contain a challenge which the user has to fulfill before being allowed to login, or authentication access, id and refresh keys
    public func authenticate(username: String, password: String, with eventLoopWithContext: AWSCognitoEventLoopWithContext) -> EventLoopFuture<AWSCognitoAuthenticateResponse> {
        return secretHashFuture(username: username, on: eventLoopWithContext.eventLoop).flatMap { secretHash in
            let authParameters : [String: String] = ["USERNAME":username,
                                                     "PASSWORD": password,
                                                     "SECRET_HASH":secretHash]
            return self.initiateAuthRequest(authFlow: .adminNoSrpAuth,
                                       authParameters: authParameters,
                                       with: eventLoopWithContext)
        }
    }

    /// Get new access and id tokens from a refresh token
    ///
    /// The username you provide here has to be the real username of the user not an alias like an email. You can get the real username by authenticing an access token
    /// - parameters:
    ///     - username: user name of user
    ///     - refreshToken: refresh token required to generate new access and id tokens
    ///     - with: Eventloop and authenticate context. You can use a Vapor request here.
    /// - returns:
    ///     - An authentication result which should include an id and status token
    public func refresh(username: String, refreshToken: String, with eventLoopWithContext: AWSCognitoEventLoopWithContext) -> EventLoopFuture<AWSCognitoAuthenticateResponse> {
        return secretHashFuture(username: username, on: eventLoopWithContext.eventLoop).flatMap { secretHash in
            let authParameters : [String: String] = ["USERNAME":username,
                                                     "REFRESH_TOKEN":refreshToken,
                                                     "SECRET_HASH":secretHash]
            return self.initiateAuthRequest(authFlow: .refreshTokenAuth,
                                           authParameters: authParameters,
                                           with: eventLoopWithContext)
        }
    }

    /// respond to authentication challenge
    ///
    /// In some situations when logging in Cognito will respond with a challenge before you are allowed to login. These could be supplying a new password for a new account,
    /// supply an MFA code. This is used to respond to those challenges. You respond with the challenge name, the session id return in the challenge and the response values required.
    /// If successful you will be returned an authenticated response which includes the access, id and refresh tokens.
    /// - parameters:
    ///     - username: User name of user
    ///     - name: Name of challenge
    ///     - responses: Challenge responses
    ///     - session: Session id returned with challenge
    ///     - with: EventLoop and authenticate context. You can use a Vapor request here.
    /// - returns:
    ///     An authentication response. This can contain another challenge which the user has to fulfill before being allowed to login, or authentication access, id and refresh keys
    public func respondToChallenge(username: String, name: AWSCognitoChallengeName, responses: [String: String], session: String?, with eventLoopWithContext: AWSCognitoEventLoopWithContext) -> EventLoopFuture<AWSCognitoAuthenticateResponse> {
        return secretHashFuture(username: username, on: eventLoopWithContext.eventLoop).flatMap { secretHash in
            var challengeResponses = responses
            challengeResponses["USERNAME"] = username
            challengeResponses["SECRET_HASH"] = secretHash
            guard let context = eventLoopWithContext.cognitoContextData else { return eventLoopWithContext.eventLoop.makeFailedFuture(AWSCognitoError.failedToCreateContextData) }
            let request = CognitoIdentityProvider.AdminRespondToAuthChallengeRequest(challengeName: name,
                                                                                     challengeResponses: challengeResponses,
                                                                                     clientId: self.configuration.clientId,
                                                                                     contextData: context,
                                                                                     session: session,
                                                                                     userPoolId: self.configuration.userPoolId)
            return self.configuration.cognitoIDP.adminRespondToAuthChallenge(request)
                .flatMapErrorThrowing { error in
                    throw self.translateError(error: error)
                }
                .flatMapThrowing { (response)->AWSCognitoAuthenticateResponse in
                    guard let authenticationResult = response.authenticationResult,
                        let accessToken = authenticationResult.accessToken,
                        let idToken = authenticationResult.idToken
                        else {
                            // if there was no tokens returned, return challenge if it exists
                            if let challengeName = response.challengeName {
                                return AWSCognitoAuthenticateResponse(challenged: AWSCognitoAuthenticateResponse.ChallengedResponse(
                                    name: challengeName.rawValue,
                                    parameters: response.challengeParameters,
                                    session: response.session))
                            }
                            throw AWSCognitoError.unexpectedResult(reason: "Authenticated response does not authentication tokens or challenge information") // should have either an authenticated result or a challenge
                    }

                    return AWSCognitoAuthenticateResponse(authenticated: AWSCognitoAuthenticateResponse.AuthenticatedResponse(
                        accessToken: accessToken,
                        idToken: idToken,
                        refreshToken: authenticationResult.refreshToken,
                        expiresIn: authenticationResult.expiresIn != nil ? Date(timeIntervalSinceNow: TimeInterval(authenticationResult.expiresIn!)) : nil))
            }
            .hop(to: eventLoopWithContext.eventLoop)
        }
    }

    /// update the users attributes
    /// - parameters:
    ///     - username: user name of user
    ///     - attributes: list of updated attributes for user
    ///     - on: Event loop request is running on.
    public func updateUserAttributes(username: String, attributes: [String: String], on eventLoop: EventLoop) -> EventLoopFuture<Void> {
        let attributes = attributes.map { CognitoIdentityProvider.AttributeType(name: $0.key, value:  $0.value) }
        let request = CognitoIdentityProvider.AdminUpdateUserAttributesRequest(userAttributes: attributes, username: username, userPoolId: configuration.userPoolId)
        return configuration.cognitoIDP.adminUpdateUserAttributes(request)
            .flatMapErrorThrowing { error in
                throw self.translateError(error: error)
            }
        .map { _ in return }
        .hop(to: eventLoop)
    }
}

extension AWSCognitoAuthenticatable {
    /// return secret hash to include in cognito identity provider calls
    func secretHash(username: String) -> String {

        let message = username + configuration.clientId
        let messageHmac: HashedAuthenticationCode<SHA256> = HMAC.authenticationCode(for: Data(message.utf8), using: SymmetricKey(data: Data(configuration.clientSecret.utf8)))
        return Data(messageHmac).base64EncodedString()
    }

    /// return future containing secret hash to include in cognito identity provider calls
    func secretHashFuture(username: String, on eventLoopGroup: EventLoopGroup) -> EventLoopFuture<String> {
        return eventLoopGroup.next().makeSucceededFuture(secretHash(username: username))
    }

    /// return an authorization request future
    func initiateAuthRequest(authFlow: CognitoIdentityProvider.AuthFlowType, authParameters: [String: String], with eventLoopWithContext: AWSCognitoEventLoopWithContext) -> EventLoopFuture<AWSCognitoAuthenticateResponse> {
        guard let context = eventLoopWithContext.cognitoContextData else {return eventLoopWithContext.eventLoop.makeFailedFuture(AWSCognitoError.failedToCreateContextData)}
        let request = CognitoIdentityProvider.AdminInitiateAuthRequest(
            authFlow: authFlow,
            authParameters: authParameters,
            clientId: configuration.clientId,
            contextData: context,
            userPoolId: configuration.userPoolId)
        return configuration.cognitoIDP.adminInitiateAuth(request)
            .flatMapErrorThrowing { error in
                throw self.translateError(error: error)
            }
            .flatMapThrowing { (response)->AWSCognitoAuthenticateResponse in
                guard let authenticationResult = response.authenticationResult,
                    let accessToken = authenticationResult.accessToken,
                    let idToken = authenticationResult.idToken
                    else {
                        // if there was no tokens returned, return challenge if it exists
                        if let challengeName = response.challengeName {
                            return AWSCognitoAuthenticateResponse(challenged: AWSCognitoAuthenticateResponse.ChallengedResponse(
                                name: challengeName.rawValue,
                                parameters: response.challengeParameters,
                                session: response.session))
                        }
                        throw AWSCognitoError.unexpectedResult(reason: "Authenticated response does not authentication tokens or challenge information") // should have either an authenticated result or a challenge
                }

                return AWSCognitoAuthenticateResponse(authenticated: AWSCognitoAuthenticateResponse.AuthenticatedResponse(
                    accessToken: accessToken,
                    idToken: idToken,
                    refreshToken: authenticationResult.refreshToken,
                    expiresIn: authenticationResult.expiresIn != nil ? Date(timeIntervalSinceNow: TimeInterval(authenticationResult.expiresIn!)) : nil))
        }
        .hop(to: eventLoopWithContext.eventLoop)
    }

    /// translate error from one thrown by aws-sdk-swift to vapor error
    func translateError(error: Error) -> Error {
        switch error {
        case CognitoIdentityProviderErrorType.notAuthorizedException(let message):
            return AWSCognitoError.unauthorized(reason: message)

        default:
            return error
        }
    }
}
