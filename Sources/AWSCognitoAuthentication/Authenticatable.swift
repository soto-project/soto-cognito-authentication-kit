import AWSSDKSwiftCore
import CognitoIdentityProvider
import JWTKit
import NIO
import OpenCrypto
import Vapor

public typealias AWSCognitoChallengeName = CognitoIdentityProvider.ChallengeNameType
public typealias AWSCognitoUserStatusType = CognitoIdentityProvider.UserStatusType

/// Response to create user
public struct AWSCognitoCreateUserResponse: Content {
    public var userName: String
    public var userStatus: AWSCognitoUserStatusType
}

/// Response to initAuth
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

public struct AWSCognitoAuthenticateResponse: Content {
    public let authenticated: AuthenticatedResponse?
    public let challenged: ChallengedResponse?

    init(authenticated: AuthenticatedResponse? = nil, challenged: ChallengedResponse? = nil) {
        self.authenticated = authenticated
        self.challenged = challenged
    }
}


/// Protocol for AWS Cognito authentication class
public protocol AWSCognitoAuthenticatable {
    /// user pool id
    static var userPoolId: String { get }
    /// app client it
    static var clientId: String { get }
    /// app client secret
    static var clientSecret: String { get }
    /// Cognito Identity Provider client
    static var cognitoIDP: CognitoIdentityProvider { get }
    /// region userpool is in
    static var region: Region { get }
    /// Json web token signers
    static var jwtSigners: JWTSigners? { get set }
}

/// public interface functions for user and token authentication
public extension AWSCognitoAuthenticatable {

    /// Sign up as AWS Cognito user.
    ///
    /// An email will be sent out with either a confirmation code or a link to confirm the user.
    /// - parameters:
    ///     - username: user name for new user
    ///     - attributes: user attributes. These should be from the list of standard claims detailed in the [OpenID spec](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims). You can include custom attiibutes by prepending them with "custom:".
    ///     - on: The event loop run aws requests on.
    /// - returns:
    ///     EventLoopFuture holding the sign up response
    static func signUp(username: String, password: String, attributes: [String:String], on eventLoop: EventLoop) -> EventLoopFuture<CognitoIdentityProvider.SignUpResponse> {
        return secretHashFuture(username: username, on: eventLoop).flatMap { secretHash in
            let userAttributes = attributes.map { return CognitoIdentityProvider.AttributeType(name: $0.key, value: $0.value) }
            let request = CognitoIdentityProvider.SignUpRequest(clientId: Self.clientId, password: password, secretHash: secretHash, userAttributes: userAttributes, username: username)
            return cognitoIDP.signUp(request)
                .flatMapErrorThrowing { error in
                    throw translateError(error: error)
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
    ///     - on: The event loop to run  aws requests on.
    /// - returns:
    ///     Empty EventLoopFuture
    static func confirmSignUp(username: String, confirmationCode: String, on eventLoop: EventLoop) -> EventLoopFuture<Void> {
        return secretHashFuture(username: username, on: eventLoop).flatMap { secretHash in
            let request = CognitoIdentityProvider.ConfirmSignUpRequest(clientId: Self.clientId, confirmationCode: confirmationCode, forceAliasCreation: false, secretHash: secretHash, username: username)
            return cognitoIDP.confirmSignUp(request)
                .flatMapErrorThrowing { error in
                    throw translateError(error: error)
                }
                .transform(to: Void())
                .hop(to: eventLoop)
        }
    }

    /// create a new AWS Cognito user.
    ///
    /// This uses AdminCreateUser. An invitation email, with a password  is sent to the user. This password requires to be renewed as soon as it is used.
    /// - parameters:
    ///     - username: user name for new user
    ///     - attributes: user attributes. These should be from the list of standard claims detailed in the [OpenID spec](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims). You can include custom attiibutes by prepending them with "custom:".
    ///     - on: The event loop run aws requests on.
    /// - returns:
    ///     EventLoopFuture holding the create user response
    static func createUser(username: String, attributes: [String:String], on eventLoop: EventLoop) -> EventLoopFuture<AWSCognitoCreateUserResponse> {
        let userAttributes = attributes.map { return CognitoIdentityProvider.AttributeType(name: $0.key, value: $0.value) }
        let request = CognitoIdentityProvider.AdminCreateUserRequest(desiredDeliveryMediums:[.email], messageAction: .resend,userAttributes: userAttributes, username: username, userPoolId: Self.userPoolId)
        return cognitoIDP.adminCreateUser(request)
            .flatMapErrorThrowing { error in
                throw translateError(error: error)
            }
            .flatMapThrowing { response in
                guard let user = response.user,
                    let username = user.username,
                    let userStatus = user.userStatus
                    else { throw Abort(.internalServerError) }
                return AWSCognitoCreateUserResponse(userName: username, userStatus: userStatus)
        }
        .hop(to: eventLoop)
    }

    /// authenticate using a username and password
    ///
    /// - parameters:
    ///     - username: user name for user
    ///     - password: password for user
    ///     - on: Vapor Request structure
    /// - returns:
    ///     An authentication response. This can contain a challenge which the user has to fulfill before being allowed to login, or authentication access, id and refresh keys
    static func authenticate(username: String, password: String, on req: Request) -> EventLoopFuture<AWSCognitoAuthenticateResponse> {
        return secretHashFuture(username: username, on: req.eventLoop).flatMap { secretHash in
            let authParameters : [String: String] = ["USERNAME":username,
                                                     "PASSWORD": password,
                                                     "SECRET_HASH":secretHash]
            return initiateAuthRequest(authFlow: .adminNoSrpAuth,
                                       authParameters: authParameters,
                                       on: req)
        }
    }

    /// Get new access and id tokens from a refresh token
    ///
    /// The username you provide here has to be the real username of the user not an alias like an email. You can get the real username by authenticing an access token
    /// - parameters:
    ///     - username: user name of user
    ///     - refreshToken: refresh token required to generate new access and id tokens
    /// - returns:
    ///     - An authentication result which should include an id and status token
    static func refresh(username: String, refreshToken: String, on req: Request) -> EventLoopFuture<AWSCognitoAuthenticateResponse> {
        return secretHashFuture(username: username, on: req.eventLoop).flatMap { secretHash in
            let authParameters : [String: String] = ["USERNAME":username,
                                                     "REFRESH_TOKEN":refreshToken,
                                                     "SECRET_HASH":secretHash]
            return initiateAuthRequest(authFlow: .refreshTokenAuth,
                                           authParameters: authParameters,
                                           on: req)
        }
    }

    /// respond to authentication challenge
    static func respondToChallenge(username: String, name: AWSCognitoChallengeName, responses: [String: String], session: String, on req: Request) -> EventLoopFuture<AWSCognitoAuthenticateResponse> {
        return secretHashFuture(username: username, on: req.eventLoop).flatMap { secretHash in
            var challengeResponses = responses
            challengeResponses["USERNAME"] = username
            challengeResponses["SECRET_HASH"] = secretHash
            let request = CognitoIdentityProvider.AdminRespondToAuthChallengeRequest(challengeName: name,
                                                                                     challengeResponses: challengeResponses,
                                                                                     clientId: Self.clientId,
                                                                                     contextData: contextData(from: req),
                                                                                     session: session,
                                                                                     userPoolId: Self.userPoolId)
            return cognitoIDP.adminRespondToAuthChallenge(request)
                .flatMapErrorThrowing { error in
                    throw translateError(error: error)
                }
                .flatMapThrowing { (response)->AWSCognitoAuthenticateResponse in
                    guard let authenticationResult = response.authenticationResult,
                        let accessToken = authenticationResult.accessToken,
                        let idToken = authenticationResult.idToken
                        else {
                            // if there was no tokens returned, return challenge if it exists
                            if let challengeName = response.challengeName {
                                return AWSCognitoAuthenticateResponse(challenged: ChallengedResponse(
                                    name: challengeName.rawValue,
                                    parameters: response.challengeParameters,
                                    session: response.session))
                            }
                            throw Abort(.unauthorized)
                    }

                    return AWSCognitoAuthenticateResponse(authenticated: AuthenticatedResponse(
                        accessToken: accessToken,
                        idToken: idToken,
                        refreshToken: authenticationResult.refreshToken,
                        expiresIn: authenticationResult.expiresIn != nil ? Date(timeIntervalSinceNow: TimeInterval(authenticationResult.expiresIn!)) : nil))
            }
            .hop(to: req.eventLoop)
        }
    }

    /// update the users attributes
    static func updateUserAttributes(username: String, attributes: [String: String], on eventLoop: EventLoop) -> EventLoopFuture<Void> {
        let attributes = attributes.map { CognitoIdentityProvider.AttributeType(name: $0.key, value:  $0.value) }
        let request = CognitoIdentityProvider.AdminUpdateUserAttributesRequest(userAttributes: attributes, username: username, userPoolId: Self.userPoolId)
        return cognitoIDP.adminUpdateUserAttributes(request)
            .flatMapErrorThrowing { error in
                throw translateError(error: error)
            }
        .transform(to: Void()).hop(to: eventLoop)
    }
}

extension AWSCognitoAuthenticatable {
    /// return secret hash to include in cognito identity provider calls
    static func secretHash(username: String) -> String {

        let message = username + Self.clientId
        let messageHmac: HashedAuthenticationCode<SHA256> = HMAC.authenticationCode(for: Data(message.utf8), using: SymmetricKey(data: Data(Self.clientSecret.utf8)))
        return Data(messageHmac).base64EncodedString()
    }

    /// return future containing secret hash to include in cognito identity provider calls
    static func secretHashFuture(username: String, on eventLoopGroup: EventLoopGroup) -> EventLoopFuture<String> {
        return eventLoopGroup.next().makeSucceededFuture(secretHash(username: username))
    }

    /// return an authorization request future
    static func initiateAuthRequest(authFlow: CognitoIdentityProvider.AuthFlowType, authParameters: [String: String], on req: Request) -> EventLoopFuture<AWSCognitoAuthenticateResponse> {
        let request = CognitoIdentityProvider.AdminInitiateAuthRequest(
            authFlow: authFlow,
            authParameters: authParameters,
            clientId: clientId,
            contextData: contextData(from: req),
            userPoolId: Self.userPoolId)
        return cognitoIDP.adminInitiateAuth(request)
            .flatMapErrorThrowing { error in
                throw translateError(error: error)
            }
            .flatMapThrowing { (response)->AWSCognitoAuthenticateResponse in
                guard let authenticationResult = response.authenticationResult,
                    let accessToken = authenticationResult.accessToken,
                    let idToken = authenticationResult.idToken
                    else {
                        // if there was no tokens returned, return challenge if it exists
                        if let challengeName = response.challengeName {
                            return AWSCognitoAuthenticateResponse(challenged: ChallengedResponse(
                                name: challengeName.rawValue,
                                parameters: response.challengeParameters,
                                session: response.session))
                        }
                        throw Abort(.unauthorized)
                }

                return AWSCognitoAuthenticateResponse(authenticated: AuthenticatedResponse(
                    accessToken: accessToken,
                    idToken: idToken,
                    refreshToken: authenticationResult.refreshToken,
                    expiresIn: authenticationResult.expiresIn != nil ? Date(timeIntervalSinceNow: TimeInterval(authenticationResult.expiresIn!)) : nil))
        }
        .hop(to: req.eventLoop)
    }

    /// create context data from Vapor request
    static func contextData(from req: Request) -> CognitoIdentityProvider.ContextDataType? {
        let host = req.headers["Host"].first ?? "localhost:8080"
        //guard let ipAddress = req.http.remotePeer.hostname ?? req.http.channel?.remoteAddress?.description else { return nil }
        let headers = req.headers.map { CognitoIdentityProvider.HttpHeader(headerName: $0.name, headerValue: $0.value) }
        let contextData = CognitoIdentityProvider.ContextDataType(
            httpHeaders: headers,
            ipAddress: "127.0.0.1",
            serverName: host,
            serverPath: req.url.path)
        return contextData
    }

    /// translate error from one thrown by aws-sdk-swift to vapor error
    static func translateError(error: Error) -> Error {
        switch error {
        case CognitoIdentityProviderErrorType.codeMismatchException(let message):
            return Abort(.badRequest, reason: message)

        case CognitoIdentityProviderErrorType.invalidPasswordException(let message),
             CognitoIdentityProviderErrorType.invalidParameterException(let message):
            return Abort(.badRequest, reason: message)

        case CognitoIdentityProviderErrorType.resourceNotFoundException(let message):
            return Abort(.notFound, reason: message)

        case CognitoIdentityProviderErrorType.notAuthorizedException(_),
             CognitoIdentityProviderErrorType.userNotFoundException(_):
            return Abort(.unauthorized)

        case CognitoIdentityProviderErrorType.usernameExistsException(_):
            return Abort(.conflict, reason:"Username already exists")

        case CognitoIdentityProviderErrorType.unsupportedUserStateException(_):
            return Abort(.conflict, reason:"Username already exists")

        case CognitoIdentityProviderErrorType.userNotConfirmedException(_):
            return Abort(.notAcceptable, reason:"User is not confirmed")

        default:
            return error
        }
    }
}
