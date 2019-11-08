import AWSSDKSwiftCore
import CognitoIdentityProvider
import Crypto
import Debugging
import JWT
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
public protocol AWSCognitoAuthenticatable: AWSCognitoConfiguration {
}

/// public interface functions for user and token authentication
public extension AWSCognitoAuthenticatable {
    
    /// sign up user. An email will be sent out with either a confirmation code or a link to confirm the user
    static func signUp(username: String, password: String, attributes: [String:String], on req: Request) -> Future<CognitoIdentityProvider.SignUpResponse> {
        return secretHashFuture(username: username, on: req).flatMap { secretHash in
            let userAttributes = attributes.map { return CognitoIdentityProvider.AttributeType(name: $0.key, value: $0.value) }
            let request = CognitoIdentityProvider.SignUpRequest(clientId: Self.clientId, password: password, secretHash: secretHash, userAttributes: userAttributes, username: username)
            return cognitoIDP.signUp(request)
                .thenIfErrorThrowing { error in
                    throw translateError(error: error)
            }
        }
    }
    
    /// confirm sign up of user
    static func confirmSignUp(username: String, confirmationCode: String, on req: Request) -> Future<Void> {
        return secretHashFuture(username: username, on: req).flatMap { secretHash in
            let request = CognitoIdentityProvider.ConfirmSignUpRequest(clientId: Self.clientId, confirmationCode: confirmationCode, forceAliasCreation: false, secretHash: secretHash, username: username)
            return cognitoIDP.confirmSignUp(request)
                .thenIfErrorThrowing { error in
                    throw translateError(error: error)
                }
                .transform(to: Void())
        }
    }
    
    /// create a new user. This uses AdminCreateUser. An invitation email, with a password  is sent to the user. This password requires to be renewed as soon as it is used.
    static func createUser(username: String, attributes: [String:String], on worker: Worker) -> Future<AWSCognitoCreateUserResponse> {
        let userAttributes = attributes.map { return CognitoIdentityProvider.AttributeType(name: $0.key, value: $0.value) }
        let request = CognitoIdentityProvider.AdminCreateUserRequest(desiredDeliveryMediums:[.email], messageAction: .resend,userAttributes: userAttributes, username: username, userPoolId: Self.userPoolId)
        return cognitoIDP.adminCreateUser(request)
            .thenIfErrorThrowing { error in
                throw translateError(error: error)
            }
            .thenThrowing { response in
                guard let user = response.user,
                    let username = user.username,
                    let userStatus = user.userStatus
                    else { throw Abort(.internalServerError) }
                return AWSCognitoCreateUserResponse(userName: username, userStatus: userStatus)
        }
        .hopTo(eventLoop: worker.next())
    }
    
    /// authenticate using a username and password
    static func authenticate(username: String, password: String, on req: Request) -> Future<AWSCognitoAuthenticateResponse> {
        return secretHashFuture(username: username, on: req).flatMap { secretHash in
            let authParameters : [String: String] = ["USERNAME":username,
                                                     "PASSWORD": password,
                                                     "SECRET_HASH":secretHash]
            return initiateAuthRequest(authFlow: .adminNoSrpAuth,
                                       authParameters: authParameters,
                                       on: req)
        }
    }
    
    /// get new access and id tokens from a refresh token
    static func refresh(username: String, refreshToken: String, on req: Request) -> Future<AWSCognitoAuthenticateResponse> {
        return secretHashFuture(username: username, on: req).flatMap { secretHash in
            let authParameters : [String: String] = ["REFRESH_TOKEN":refreshToken,
                                                     "SECRET_HASH":secretHash]
            return initiateAuthRequest(authFlow: .refreshTokenAuth,
                                           authParameters: authParameters,
                                           on: req)
        }
    }

    /// respond to authentication challenge
    static func respondToChallenge(username: String, name: AWSCognitoChallengeName, responses: [String: String], session: String, on req: Request) -> Future<AWSCognitoAuthenticateResponse> {
        return secretHashFuture(username: username, on: req).flatMap { secretHash in
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
                .thenIfErrorThrowing { error in
                    throw translateError(error: error)
                }
                .map { (response)->AWSCognitoAuthenticateResponse in
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
            .hopTo(eventLoop: req.next())
        }
    }
    
    /// update the users attributes
    static func updateUserAttributes(username: String, attributes: [String: String], on worker: Worker) -> Future<Void> {
        let attributes = attributes.map { CognitoIdentityProvider.AttributeType(name: $0.key, value:  $0.value) }
        let request = CognitoIdentityProvider.AdminUpdateUserAttributesRequest(userAttributes: attributes, username: username, userPoolId: Self.userPoolId)
        return cognitoIDP.adminUpdateUserAttributes(request)
            .thenIfErrorThrowing { error in
                throw translateError(error: error)
            }
            .transform(to: Void()).hopTo(eventLoop: worker.next())
    }
}

extension AWSCognitoAuthenticatable {
    /// return secret hash to include in cognito identity provider calls
    static func secretHash(username: String) throws -> String {
        let hmac = HMAC(algorithm: .sha256)
        let message = username + Self.clientId
        let messageHmac = try Data(hmac.authenticate(message, key: Self.clientSecret))
        return messageHmac.base64EncodedString()
    }

    /// return future containing secret hash to include in cognito identity provider calls
    static func secretHashFuture(username: String, on worker: Worker) -> Future<String> {
        do {
            return try worker.future(secretHash(username: username))
        } catch {
            return worker.future(error: error)
        }
    }

    /// return an authorization request future
    static func initiateAuthRequest(authFlow: CognitoIdentityProvider.AuthFlowType, authParameters: [String: String], on req: Request) -> Future<AWSCognitoAuthenticateResponse> {
        let request = CognitoIdentityProvider.AdminInitiateAuthRequest(
            authFlow: authFlow,
            authParameters: authParameters,
            clientId: clientId,
            contextData: contextData(from: req),
            userPoolId: Self.userPoolId)
        return cognitoIDP.adminInitiateAuth(request)
            .thenIfErrorThrowing { error in
                throw translateError(error: error)
            }
            // map AWS response to AWSCognitoAuthenticateResponse
            .map { (response)->AWSCognitoAuthenticateResponse in
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
        .hopTo(eventLoop: req.next())
    }

    /// create context data from Vapor request
    static func contextData(from req: Request) -> CognitoIdentityProvider.ContextDataType? {
        let host = req.http.headers["Host"].first ?? "localhost:8080"
        guard let ipAddress = req.http.remotePeer.hostname ?? req.http.channel?.remoteAddress?.description else { return nil }
        let headers = req.http.headers.map { CognitoIdentityProvider.HttpHeader(headerName: $0.name, headerValue: $0.value) }
        let contextData = CognitoIdentityProvider.ContextDataType(
            httpHeaders: headers,
            ipAddress: ipAddress,
            serverName: host,
            serverPath: req.http.urlString)
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

