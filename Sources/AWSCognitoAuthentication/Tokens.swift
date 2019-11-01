import JWT
import Vapor

public protocol AWSCognitoPayloadToken: JWTPayload {}

public struct AWSCognitoAccessToken<Config: AWSCognitoConfiguration>: AWSCognitoPayloadToken, Content {
    let authenticationTime: Date
    let expirationTime: Date
    let issuedAt: Date
    let issuer: String
    let scope: String
    let subject: String
    let tokenUse: String
    let username: String

    public func verify(using signer: JWTSigner) throws {
        guard expirationTime > Date() else {throw Abort(.unauthorized, reason:"token expired")}
        guard issuer == "https://cognito-idp.\(Config.region.rawValue).amazonaws.com/\(Config.userPoolId)" else {throw Abort(.unauthorized)}
        guard tokenUse == "access" else {throw Abort(.unauthorized)}
    }

    private enum CodingKeys: String, CodingKey {
        case authenticationTime = "auth_time"
        case expirationTime = "exp"
        case issuedAt = "iat"
        case issuer = "iss"
        case scope = "scope"
        case subject = "sub"
        case tokenUse = "token_use"
        case username = "username"
    }
}

public struct AWSCognitoIdToken<Config: AWSCognitoConfiguration>: AWSCognitoPayloadToken, Content {
    let audience: String
    let authenticationTime: Date
    let email: String?
    let email_verified: Bool?
    let expirationTime: Date
    let issuedAt: Date
    let issuer: String
    let subject: String
    let username: String
    let tokenUse: String

    public func verify(using signer: JWTSigner) throws {
        guard expirationTime > Date() else {throw Abort(.unauthorized, reason:"token expired")}
        guard audience == Config.clientId else {throw Abort(.unauthorized)}
        guard issuer == "https://cognito-idp.\(Config.region.rawValue).amazonaws.com/\(Config.userPoolId)" else {throw Abort(.unauthorized)}
        guard tokenUse == "id" else {throw Abort(.unauthorized)}
    }

    private enum CodingKeys: String, CodingKey {
        case audience = "aud"
        case authenticationTime = "auth_time"
        case email = "email"
        case email_verified = "email_verified"
        case expirationTime = "exp"
        case issuedAt = "iat"
        case issuer = "iss"
        case subject = "sub"
        case tokenUse = "token_use"
        case username = "cognito:username"
    }
}
