@_exported import AWSCognitoIdentityProvider
@_exported import JWTKit

import AWSSDKSwiftCore
import Foundation
import NIO
import Crypto

public typealias AWSCognitoChallengeName = CognitoIdentityProvider.ChallengeNameType
public typealias AWSCognitoUserStatusType = CognitoIdentityProvider.UserStatusType

public enum AWSCognitoError: Error {
    case failedToCreateContextData
    case unexpectedResult(reason: String?)
    case unauthorized(reason: String?)
    case invalidPublicKey
}

/// Response to create user
public struct AWSCognitoCreateUserResponse: Codable {
    public var userName: String
    public var userStatus: AWSCognitoUserStatusType
}

/// Authentication response
public enum AWSCognitoAuthenticateResponse: Codable {
    /// response with authentication details
    case authenticated(AuthenticatedResponse)
    /// response containing a challenge
    case challenged(ChallengedResponse)
    
    public struct AuthenticatedResponse: Codable {
        public let accessToken : String?
        public let idToken : String?
        public let refreshToken : String?
        public let expiresIn: Date?
    }

    public struct ChallengedResponse: Codable {
        public let name: String?
        public let parameters: [String: String]?
        public let session: String?
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        if let authenticated = try container.decodeIfPresent(AuthenticatedResponse.self, forKey: .authenticated) {
            self = .authenticated(authenticated)
        } else if let challenged = try container.decodeIfPresent(ChallengedResponse.self, forKey: .challenged) {
            self = .challenged(challenged)
        } else {
            throw DecodingError.valueNotFound(AWSCognitoAuthenticateResponse.self, .init(codingPath: decoder.codingPath, debugDescription: "No valid response found"))
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
    ///     - clientMetadata: A map of custom key-value pairs that you can provide as input for AWS Lambda custom workflows
    ///     - on: Event loop request is running on.
    /// - returns:
    ///     EventLoopFuture holding the sign up response
    public func signUp(
        username: String,
        password: String,
        attributes: [String:String],
        clientMetadata: [String: String]? = nil,
        on eventLoop: EventLoop
    ) -> EventLoopFuture<CognitoIdentityProvider.SignUpResponse> {
        return secretHashFuture(username: username, on: eventLoop).flatMap { secretHash in
            let userAttributes = attributes.map { return CognitoIdentityProvider.AttributeType(name: $0.key, value: $0.value) }
            let request = CognitoIdentityProvider.SignUpRequest(
                clientId: self.configuration.clientId,
                clientMetadata: clientMetadata,
                password: password,
                secretHash: secretHash,
                userAttributes: userAttributes,
                username: username)
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
    ///     - clientMetadata: A map of custom key-value pairs that you can provide as input for AWS Lambda custom workflows
    ///     - on: Event loop request is running on.
    /// - returns:
    ///     Empty EventLoopFuture
    public func confirmSignUp(username: String, confirmationCode: String, clientMetadata: [String: String]? = nil, on eventLoop: EventLoop) -> EventLoopFuture<Void> {
        return secretHashFuture(username: username, on: eventLoop).flatMap { secretHash in
            let request = CognitoIdentityProvider.ConfirmSignUpRequest(
                clientId: self.configuration.clientId,
                clientMetadata: clientMetadata,
                confirmationCode: confirmationCode,
                forceAliasCreation: false,
                secretHash: secretHash,
                username: username)
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
    /// This uses AdminCreateUser. An invitation email, with a password  is sent to the user. This password requires to be renewed as soon as it is used. As this function uses an Admin
    /// function it requires a CognitoIdentityProvider with AWS credentials.
    /// - parameters:
    ///     - username: user name for new user
    ///     - attributes: user attributes. These should be from the list of standard claims detailed in the [OpenID spec](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims) . You can include custom attiibutes by prepending them with "custom:".
    ///     - messageAction: If this is set to `.resend` this will resend the message for an existing user. If this is set to `.suppress` the message sending is suppressed.
    ///     - clientMetadata: A map of custom key-value pairs that you can provide as input for AWS Lambda custom workflows
    ///     - on: Event loop request is running on.
    /// - returns:
    ///     EventLoopFuture holding the create user response
    public func createUser(
        username: String,
        attributes: [String:String],
        temporaryPassword: String? = nil,
        messageAction: CognitoIdentityProvider.MessageActionType? = nil,
        clientMetadata: [String: String]? = nil,
        on eventLoop: EventLoop
    ) -> EventLoopFuture<AWSCognitoCreateUserResponse> {
        let userAttributes = attributes.map { return CognitoIdentityProvider.AttributeType(name: $0.key, value: $0.value) }
        let request = CognitoIdentityProvider.AdminCreateUserRequest(
            clientMetadata: clientMetadata,
            desiredDeliveryMediums:[.email],
            messageAction: messageAction,
            temporaryPassword: temporaryPassword,
            userAttributes: userAttributes,
            username: username,
            userPoolId: configuration.userPoolId)
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

    /// Authenticate using a username and password.
    /// This function uses the Admin version of the initiateAuthRequest so your CognitoIdentityProvider should be setup with AWS credentials.
    ///
    /// - parameters:
    ///     - username: user name for user
    ///     - password: password for user
    ///     - requireAuthenticatedClient: Do we need a CognitoIdentityProvider with AWS credentials
    ///     - clientMetadata: A map of custom key-value pairs that you can provide as input for AWS Lambda custom workflows
    ///     - context: Context data for this request
    ///     - on: Eventloop request should run on.
    /// - returns:
    ///     An authentication response. This can contain a challenge which the user has to fulfill before being allowed to login, or authentication access, id and refresh keys
    public func authenticate(
        username: String,
        password: String,
        requireAuthenticatedClient: Bool = true,
        clientMetadata: [String: String]? = nil,
        context: AWSCognitoContextData,
        on eventLoop: EventLoop
    ) -> EventLoopFuture<AWSCognitoAuthenticateResponse> {
        return secretHashFuture(username: username, on: eventLoop).flatMap { secretHash in
            let authParameters : [String: String] = ["USERNAME":username,
                                                     "PASSWORD": password,
                                                     "SECRET_HASH":secretHash]
            return self.initiateAuthRequest(authFlow: .adminUserPasswordAuth,
                                            authParameters: authParameters,
                                            requireAuthenticatedClient: requireAuthenticatedClient,
                                            clientMetadata: clientMetadata,
                                            context: context,
                                            on: eventLoop)
        }
    }

    /// Get new access and id tokens from a refresh token
    ///
    /// The username you provide here has to be the real username of the user not an alias like an email. You can get the real username by authenticing an access token
    /// - parameters:
    ///     - username: user name of user
    ///     - refreshToken: refresh token required to generate new access and id tokens
    ///     - requireAuthenticatedClient: Do we need a CognitoIdentityProvider with AWS credentials
    ///     - clientMetadata: A map of custom key-value pairs that you can provide as input for AWS Lambda custom workflows
    ///     - context: Context data for this request
    ///     - on: Eventloop request should run on.
    /// - returns:
    ///     - An authentication result which should include an id and status token
    public func refresh(
        username: String,
        refreshToken: String,
        requireAuthenticatedClient: Bool = true,
        clientMetadata: [String: String]? = nil,
        context: AWSCognitoContextData,
        on eventLoop: EventLoop
    ) -> EventLoopFuture<AWSCognitoAuthenticateResponse> {
        return secretHashFuture(username: username, on: eventLoop).flatMap { secretHash in
            let authParameters : [String: String] = ["USERNAME":username,
                                                     "REFRESH_TOKEN":refreshToken,
                                                     "SECRET_HASH":secretHash]
            return self.initiateAuthRequest(authFlow: .refreshTokenAuth,
                                           authParameters: authParameters,
                                           requireAuthenticatedClient: requireAuthenticatedClient,
                                           clientMetadata: clientMetadata,
                                           context: context,
                                           on: eventLoop)
        }
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
    ///     - requireAuthentication: Do we need a CognitoIdentityProvider with AWS credentials
    ///     - clientMetadata: A map of custom key-value pairs that you can provide as input for AWS Lambda custom workflows
    ///     - context: Context data for this request
    ///     - on: Eventloop request should run on.
    /// - returns:
    ///     An authentication response. This can contain another challenge which the user has to fulfill before being allowed to login, or authentication access, id and refresh keys
    public func respondToChallenge(username: String, name: AWSCognitoChallengeName, responses: [String: String], session: String?, requireAuthentication: Bool = true, clientMetadata: [String: String]? = nil, context: AWSCognitoContextData, on eventLoop: EventLoop) -> EventLoopFuture<AWSCognitoAuthenticateResponse> {
        return secretHashFuture(username: username, on: eventLoop).flatMap { secretHash in
            var challengeResponses = responses
            challengeResponses["USERNAME"] = username
            challengeResponses["SECRET_HASH"] = secretHash
            
            let respondFuture: EventLoopFuture<CognitoIdentityProvider.AdminRespondToAuthChallengeResponse>
            // If authentication required that use admin version of RespondToAuthChallenge
            if requireAuthentication {
                guard let context = context.contextData else { return eventLoop.makeFailedFuture(AWSCognitoError.failedToCreateContextData) }
                let request = CognitoIdentityProvider.AdminRespondToAuthChallengeRequest(challengeName: name,
                                                                                         challengeResponses: challengeResponses,
                                                                                         clientId: self.configuration.clientId,
                                                                                         clientMetadata: clientMetadata,
                                                                                         contextData: context,
                                                                                         session: session,
                                                                                         userPoolId: self.configuration.userPoolId)
                respondFuture = self.configuration.cognitoIDP.adminRespondToAuthChallenge(request)
            } else {
                let request = CognitoIdentityProvider.RespondToAuthChallengeRequest(challengeName: name,
                                                                                    challengeResponses: challengeResponses,
                                                                                    clientId: self.configuration.clientId,
                                                                                    clientMetadata: clientMetadata,
                                                                                    session: session)
                respondFuture = self.configuration.cognitoIDP.respondToAuthChallenge(request).map { response in
                    return CognitoIdentityProvider.AdminRespondToAuthChallengeResponse(authenticationResult: response.authenticationResult, challengeName: response.challengeName, challengeParameters: response.challengeParameters, session: response.session)
                }
            }
            
            return respondFuture.flatMapErrorThrowing { error in
                    throw self.translateError(error: error)
                }
                .flatMapThrowing { (response)->AWSCognitoAuthenticateResponse in
                    guard let authenticationResult = response.authenticationResult,
                        let accessToken = authenticationResult.accessToken,
                        let idToken = authenticationResult.idToken
                        else {
                            // if there was no tokens returned, return challenge if it exists
                            if let challengeName = response.challengeName {
                                return .challenged(.init(
                                    name: challengeName.rawValue,
                                    parameters: response.challengeParameters,
                                    session: response.session)
                                )
                            }
                            throw AWSCognitoError.unexpectedResult(reason: "Authenticated response does not authentication tokens or challenge information") // should have either an authenticated result or a challenge
                    }

                    return .authenticated(.init(
                        accessToken: accessToken,
                        idToken: idToken,
                        refreshToken: authenticationResult.refreshToken,
                        expiresIn: authenticationResult.expiresIn != nil ? Date(timeIntervalSinceNow: TimeInterval(authenticationResult.expiresIn!)) : nil
                    ))
            }
            .hop(to: eventLoop)
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
    public func respondToNewPasswordChallenge(username: String, password: String, session: String?, context: AWSCognitoContextData, on eventLoop: EventLoop) -> EventLoopFuture<AWSCognitoAuthenticateResponse> {
        return respondToChallenge(username: username, name: .newPasswordRequired, responses: ["NEW_PASSWORD":password], session: session, context: context, on: eventLoop)
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
    public func respondToMFAChallenge(username: String, token: String, session: String?, context: AWSCognitoContextData, on eventLoop: EventLoop) -> EventLoopFuture<AWSCognitoAuthenticateResponse> {
        return respondToChallenge(username: username, name: .smsMfa, responses: ["SMS_MFA_CODE":token], session: session, context: context, on: eventLoop)
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

public extension AWSCognitoAuthenticatable {
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
    func initiateAuthRequest(
        authFlow: CognitoIdentityProvider.AuthFlowType,
        authParameters: [String: String],
        requireAuthenticatedClient: Bool,
        clientMetadata: [String: String]? = nil,
        context: AWSCognitoContextData,
        on eventLoop: EventLoop
    ) -> EventLoopFuture<AWSCognitoAuthenticateResponse> {
        let initAuthFuture: EventLoopFuture<CognitoIdentityProvider.AdminInitiateAuthResponse>
        if requireAuthenticatedClient {
            guard let context = context.contextData else {return eventLoop.makeFailedFuture(AWSCognitoError.failedToCreateContextData)}
            let request = CognitoIdentityProvider.AdminInitiateAuthRequest(
                authFlow: authFlow,
                authParameters: authParameters,
                clientId: configuration.clientId,
                clientMetadata: clientMetadata,
                contextData: context,
                userPoolId: configuration.userPoolId)
            initAuthFuture = configuration.cognitoIDP.adminInitiateAuth(request)
        } else {
            let request = CognitoIdentityProvider.InitiateAuthRequest(
                authFlow: authFlow,
                authParameters: authParameters,
                clientId: configuration.clientId,
                clientMetadata: clientMetadata)
            initAuthFuture = configuration.cognitoIDP.initiateAuth(request).map { response in
                return CognitoIdentityProvider.AdminInitiateAuthResponse(authenticationResult: response.authenticationResult, challengeName: response.challengeName, challengeParameters: response.challengeParameters, session: response.session)
            }
        }
        return initAuthFuture.flatMapErrorThrowing { error in
                throw self.translateError(error: error)
            }
            .flatMapThrowing { (response)->AWSCognitoAuthenticateResponse in
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
                            ))
                        }
                        throw AWSCognitoError.unexpectedResult(reason: "Authenticated response does not authentication tokens or challenge information") // should have either an authenticated result or a challenge
                }

                return .authenticated(.init(
                    accessToken: accessToken,
                    idToken: idToken,
                    refreshToken: authenticationResult.refreshToken,
                    expiresIn: authenticationResult.expiresIn != nil ? Date(timeIntervalSinceNow: TimeInterval(authenticationResult.expiresIn!)) : nil
                ))
        }
        .hop(to: eventLoop)
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
