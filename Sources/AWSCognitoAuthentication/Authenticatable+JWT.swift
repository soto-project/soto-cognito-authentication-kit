import AsyncHTTPClient
import AWSSDKSwiftCore
import JWTKit
import NIO
import Vapor

/// struct returning when authenticating an access token
public struct AWSCognitoAccessToken: Codable {
    public let username: String
    public let subject: UUID

    private enum CodingKeys: String, CodingKey {
        case username = "username"
        case subject = "sub"
    }
}

public extension AWSCognitoAuthenticatable {
    /// verify IdToken JWT and return contents
    static func authenticate<Payload: Codable>(idToken: String, on eventLoopGroup: EventLoopGroup) -> EventLoopFuture<Payload> {
        return loadSigners(region: .euwest1, on: eventLoopGroup)
            .flatMapThrowing { signers in
                guard let tokenData = idToken.data(using: .utf8) else { throw Abort(.unauthorized) }
                let jwt = try JWT<VerifiedToken<IdTokenVerifier<Self>, Payload>>(from: tokenData, verifiedBy: signers)
                return jwt.payload.payload
        }
    }

    /// verify AccessToken JWT and return contents
    static func authenticate(accessToken: String, on eventLoopGroup: EventLoopGroup) -> EventLoopFuture<AWSCognitoAccessToken> {
        return loadSigners(region: .euwest1, on: eventLoopGroup)
            .flatMapThrowing { signers in
                guard let tokenData = accessToken.data(using: .utf8) else { throw Abort(.unauthorized) }
                do {
                    let jwt = try JWT<VerifiedToken<AccessTokenVerifier<Self>, AWSCognitoAccessToken>>(from: tokenData, verifiedBy: signers)
                    return jwt.payload.payload
                } catch DecodingError.keyNotFound(let key, _) {
                    throw Abort(.unauthorized, reason: "This is not an access Token. Field '\(key.stringValue)' is missing")
                }
        }
    }
}

extension AWSCognitoAuthenticatable {
    /// load JSON web keys and create JWT signers from them
    static func loadSigners(region: Region, on eventLoopGroup: EventLoopGroup) -> EventLoopFuture<JWTSigners> {
        // check we haven't already loaded the jwt signing key set
        guard Self.jwtSigners == nil else { return eventLoopGroup.future(Self.jwtSigners!)}

        let JWTSignersURL = "https://cognito-idp.\(region.rawValue).amazonaws.com/\(Self.userPoolId)/.well-known/jwks.json"

        return AsyncHTTPClient.HTTPClient(eventLoopGroupProvider:.shared(eventLoopGroup))
            .get(url: JWTSignersURL, deadline: .now() + TimeAmount.seconds(10))
            .flatMapThrowing { response in
                let signers = JWTSigners()
                guard let body = response.body else { return JWTSigners() }
                if let data = body.getString(at: body.readerIndex, length: body.readableBytes) {
                    try signers.use(jwksJSON: data)
                }
                return signers
        }
    }
}
