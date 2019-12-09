import AsyncHTTPClient
import AWSSDKSwiftCore
import Foundation
import JWTKit
import NIO
import Vapor

/// struct returned when authenticating an access token
public struct AWSCognitoAccessToken: Codable {
    public let username: String
    public let subject: UUID
    public let expirationTime: Date

    private enum CodingKeys: String, CodingKey {
        case username = "username"
        case subject = "sub"
        case expirationTime = "exp"
    }
}

/// Public interface functions for authenticating with CognitoIdentityProvider access and id tokens
public extension AWSCognitoAuthenticatable {
    /// Verify id Token JWT and return contents
    ///
    /// This function verifies the id token signature, verifies it was issued by your user pool, it was generated for your application client, that it hasn't
    /// expired and that it is an id token.
    /// Then it fills out the placeholder type `Payload`with values from the id token. The list of standard list of claims found in an id token are
    /// detailed in the [OpenID spec](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims) . Your
    /// `Payload` type needs to decode using these tags, plus the AWS specific "cognito:username" tag and any custom tags you have setup
    /// for the user pool.
    /// - parameters:
    ///     - idToken: Id token, returned from login
    ///     - on: Event loop to run on
    /// - returns:
    ///     An event loop future containing the payload structure.
    static func authenticate<Payload: Codable>(idToken: String, on eventLoopGroup: EventLoopGroup) -> EventLoopFuture<Payload> {
        return loadSigners(region: Self.region, on: eventLoopGroup)
            .flatMapThrowing { signers in
                let jwtPayload = try signers.verify(idToken, as: VerifiedToken<IdTokenVerifier<Self>, Payload>.self)
                return jwtPayload.payload
        }
    }

    /// Verify access token JWT and return contents
    ///
    /// This function verifies the access token signature, verifies it was issued by your user pool, that it hasn't expired and that it is an access token.
    /// - parameters:
    ///     - accessToken: Access token, returned from login
    ///     - on: Event loop to run on
    /// - returns:
    ///     An event loop future returning a structure with the username and UUID for the user.
    static func authenticate(accessToken: String, on eventLoopGroup: EventLoopGroup) -> EventLoopFuture<AWSCognitoAccessToken> {
        return loadSigners(region: Self.region, on: eventLoopGroup)
            .flatMapThrowing { signers in
                let jwtPayload = try signers.verify(accessToken, as: VerifiedToken<AccessTokenVerifier<Self>, AWSCognitoAccessToken>.self)
                return jwtPayload.payload
        }
    }
    
    /// helper function that returns if request with bearer token is cognito access authenticated
    /// - parameters:
    ///     - req: Vapor Request structure
    /// - returns:
    ///     An access token object that contains the user name and id
    static func authenticateAccessToken(_ req: Request) -> EventLoopFuture<AWSCognitoAccessToken> {
        guard let bearer = req.headers.bearerAuthorization else {
            return req.eventLoop.makeFailedFuture(AWSCognitoError.unauthorized(reason: "No bearer token"))
        }
        return authenticate(accessToken: bearer.token, on: req.eventLoop)
    }
    
    /// helper function that returns if request with bearer token is cognito id authenticated and returns contents in the payload type
    /// - parameters:
    ///     - req: Vapor Request structure
    /// - returns:
    ///     The payload contained in the token. See `authenticate<Payload: Codable>(idToken:on:)` for more details
    static func authenticateIdToken<Payload: Codable>(_ req: Request) -> EventLoopFuture<Payload> {
        guard let bearer = req.headers.bearerAuthorization else {
            return req.eventLoop.makeFailedFuture(AWSCognitoError.unauthorized(reason: "No bearer token"))
        }
        return authenticate(idToken: bearer.token, on: req.eventLoop)
    }
}

extension AWSCognitoAuthenticatable {
    /// load JSON web keys and create JWT signers from them
    static func loadSigners(region: Region, on eventLoopGroup: EventLoopGroup) -> EventLoopFuture<JWTSigners> {
        // check we haven't already loaded the jwt signing key set
        guard Self.jwtSigners == nil else { return eventLoopGroup.future(Self.jwtSigners!)}

        let JWTSignersURL = "https://cognito-idp.\(region.rawValue).amazonaws.com/\(Self.userPoolId)/.well-known/jwks.json"
        let httpClient = AsyncHTTPClient.HTTPClient(eventLoopGroupProvider:.shared(eventLoopGroup))
        return httpClient
            .get(url: JWTSignersURL, deadline: .now() + TimeAmount.seconds(10))
            .always { _ in try? httpClient.syncShutdown() }
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
