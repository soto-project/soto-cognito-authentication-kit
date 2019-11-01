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
public struct AWSCognitoAuthenticateResponse: Content {
    public var accessToken : String?
    public var idToken : String?
    public var refreshToken : String?
    public var expiresIn: Date?
    public var deviceKey: String?
    public var challengeName: String?
    public var challengeParameters: [String: String]?
    public var session: String?
}

///
public protocol AWSCognitoAuthenticatable: AWSCognitoConfiguration, Decodable {
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
    static func initiateAuthRequest(authFlow: CognitoIdentityProvider.AuthFlowType, authParameters: [String: String], on worker: Worker) -> Future<AWSCognitoAuthenticateResponse> {
        let request = CognitoIdentityProvider.AdminInitiateAuthRequest(
            authFlow: authFlow,
            authParameters: authParameters,
            clientId: clientId,
            userPoolId: Self.userPoolId)
        return cognitoIDP.adminInitiateAuth(request)
            .thenIfErrorThrowing { error in
                switch error {
                case CognitoIdentityProviderErrorType.notAuthorizedException(_),
                     CognitoIdentityProviderErrorType.userNotFoundException(_):
                    throw Abort(.unauthorized)
                default:
                    throw error
                }
            }
            .map { (response)->AWSCognitoAuthenticateResponse in
                guard let authenticationResult = response.authenticationResult,
                    let accessToken = authenticationResult.accessToken,
                    let idToken = authenticationResult.idToken
                    else {
                        // if there was no tokens returned, return challenge if it exists
                        if let challengeName = response.challengeName {
                            return AWSCognitoAuthenticateResponse(challengeName: challengeName.rawValue,
                                                 challengeParameters: response.challengeParameters,
                                                 session: response.session)
                        }
                        throw Abort(.unauthorized)
                }
                
                return AWSCognitoAuthenticateResponse(accessToken: accessToken,
                                     idToken: idToken,
                                     refreshToken: authenticationResult.refreshToken,
                                     expiresIn: authenticationResult.expiresIn != nil ? Date(timeIntervalSinceNow: TimeInterval(authenticationResult.expiresIn!)) : nil,
                                     deviceKey: authenticationResult.newDeviceMetadata?.deviceKey)
        }
        .hopTo(eventLoop: worker.next())
    }
}

public extension AWSCognitoAuthenticatable {
    
    /// create a new user
    static func createUser(username: String, attributes: [String:String], on worker: Worker) -> Future<AWSCognitoCreateUserResponse> {
        let userAttributes = attributes.map { return CognitoIdentityProvider.AttributeType(name: $0.key, value: $0.value) }
        let request = CognitoIdentityProvider.AdminCreateUserRequest(desiredDeliveryMediums:[.email], userAttributes: userAttributes, username: username, userPoolId: Self.userPoolId)
        return cognitoIDP.adminCreateUser(request)
            .thenIfErrorThrowing { error in
                switch error {
                case CognitoIdentityProviderErrorType.usernameExistsException(_):
                    throw Abort(.conflict, reason:"Username already exists")
                case CognitoIdentityProviderErrorType.invalidParameterException(let message):
                    throw Abort(.badRequest, reason: message)
                default:
                    throw error
                }
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
    static func authenticate(username: String, password: String, deviceKey: String? = nil, on worker: Worker) -> Future<AWSCognitoAuthenticateResponse> {
        return secretHashFuture(username: username, on: worker).flatMap { secretHash in
            var authParameters : [String: String] = ["USERNAME":username,
                                                     "PASSWORD": password,
                                                     "SECRET_HASH":secretHash]
            authParameters["DEVICE_KEY"] = deviceKey
            return initiateAuthRequest(authFlow: .adminNoSrpAuth,
                                       authParameters: authParameters,
                                       on: worker)
        }
    }
    
    /// get new access and id tokens from a refresh token
    static func refresh(username: String, refreshToken: String, deviceKey: String? = nil, on worker: Worker) -> Future<AWSCognitoAuthenticateResponse> {
        return secretHashFuture(username: username, on: worker).flatMap { secretHash in
            var authParameters : [String: String] = ["REFRESH_TOKEN":refreshToken,
                                                     "SECRET_HASH":secretHash]
            authParameters["DEVICE_KEY"] = deviceKey
            return initiateAuthRequest(authFlow: .refreshTokenAuth,
                                           authParameters: authParameters,
                                           on: worker)
        }
    }

    /// respond to authentication challenge
    static func respondToChallenge(username: String, name: AWSCognitoChallengeName, responses: [String: String], session: String, on worker: Worker) -> Future<AWSCognitoAuthenticateResponse> {
        return secretHashFuture(username: username, on: worker).flatMap { secretHash in
            var challengeResponses = responses
            challengeResponses["USERNAME"] = username
            challengeResponses["SECRET_HASH"] = secretHash
            let request = CognitoIdentityProvider.AdminRespondToAuthChallengeRequest(challengeName: name,
                                                                                     challengeResponses: challengeResponses,
                                                                                     clientId: Self.clientId,
                                                                                     session: session,
                                                                                     userPoolId: Self.userPoolId)
            return cognitoIDP.adminRespondToAuthChallenge(request)
                .thenIfErrorThrowing { error in
                    switch error {
                    case CognitoIdentityProviderErrorType.codeMismatchException(_):
                        throw Abort(.badRequest)
                    case CognitoIdentityProviderErrorType.notAuthorizedException(_):
                        throw Abort(.unauthorized)
                    case CognitoIdentityProviderErrorType.invalidPasswordException(let message):
                        throw Abort(.badRequest, reason: message)
                    default:
                        throw error
                    }
                }
                .map { (response)->AWSCognitoAuthenticateResponse in
                    guard let authenticationResult = response.authenticationResult,
                        let accessToken = authenticationResult.accessToken,
                        let idToken = authenticationResult.idToken
                        else {
                            // if there was no tokens returned, return challenge if it exists
                            if let challengeName = response.challengeName {
                                return AWSCognitoAuthenticateResponse(challengeName: challengeName.rawValue,
                                                     challengeParameters: response.challengeParameters,
                                                     session: response.session)
                            }
                            throw Abort(.unauthorized)
                    }
                    
                    return AWSCognitoAuthenticateResponse(accessToken: accessToken,
                                         idToken: idToken,
                                         refreshToken: authenticationResult.refreshToken,
                                         expiresIn: authenticationResult.expiresIn != nil ? Date(timeIntervalSinceNow: TimeInterval(authenticationResult.expiresIn!)) : nil,
                                         deviceKey: authenticationResult.newDeviceMetadata?.deviceKey)
            }
            .hopTo(eventLoop: worker.next())
        }
    }
}

