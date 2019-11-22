import JWTKit

/// JWT Access token
struct AccessTokenVerifier<Config: AWSCognitoAuthenticatable>: JWTPayload {
    let expirationTime: Date
    let issuer: String
    let tokenUse: String

    func verify(using signer: JWTSigner) throws {
        guard expirationTime > Date() else {throw AWSCognitoError.unauthorized(reason:"token expired")}
        guard issuer == "https://cognito-idp.\(Config.region.rawValue).amazonaws.com/\(Config.userPoolId)" else {
            throw AWSCognitoError.unauthorized(reason:"invalid token")
        }
        guard tokenUse == "access" else {throw AWSCognitoError.unauthorized(reason:"invalid token")}
    }

    private enum CodingKeys: String, CodingKey {
        case expirationTime = "exp"
        case issuer = "iss"
        case tokenUse = "token_use"
    }
}

/// JWT Id token
struct IdTokenVerifier<Config: AWSCognitoAuthenticatable>: JWTPayload {
    let audience: String
    let expirationTime: Date
    let issuer: String
    let tokenUse: String

    func verify(using signer: JWTSigner) throws {
        guard audience == Config.clientId else {throw AWSCognitoError.unauthorized(reason:"invalid token")}
        guard expirationTime > Date() else {throw AWSCognitoError.unauthorized(reason:"token expired")}
        guard issuer == "https://cognito-idp.\(Config.region.rawValue).amazonaws.com/\(Config.userPoolId)" else {
            throw AWSCognitoError.unauthorized(reason:"invalid token")
        }
        guard tokenUse == "id" else {throw AWSCognitoError.unauthorized(reason:"invalid token")}
    }

    private enum CodingKeys: String, CodingKey {
        case audience = "aud"
        case expirationTime = "exp"
        case issuer = "iss"
        case tokenUse = "token_use"
    }
}

/// JWT payload that encapsulates both a verified token and an output payload
struct VerifiedToken<Token: JWTPayload, Payload: Codable>: JWTPayload {
    let token: Token
    let payload: Payload

    init(from decoder: Decoder) throws {
        token = try Token(from: decoder)
        payload = try Payload(from: decoder)
    }

    func verify(using signer: JWTSigner) throws {
        try token.verify(using: signer)
    }
}
