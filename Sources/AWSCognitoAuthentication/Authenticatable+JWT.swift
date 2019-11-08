import AWSSDKSwiftCore
import JWT
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
    static func authenticate<Payload: Codable>(idToken: String, on worker: Worker) -> Future<Payload> {
        return loadSigners(region: .euwest1, on: worker)
            .thenThrowing { signers in
                guard let tokenData = idToken.data(using: .utf8) else { throw Abort(.unauthorized) }
                let jwt = try JWT<VerifiedToken<IdTokenVerifier<Self>, Payload>>(from: tokenData, verifiedUsing: signers)
                return jwt.payload.payload
        }
    }

    /// verify AccessToken JWT and return contents
    static func authenticate(accessToken: String, on worker: Worker) -> Future<AWSCognitoAccessToken> {
        return loadSigners(region: .euwest1, on: worker)
            .thenThrowing { signers in
                guard let tokenData = accessToken.data(using: .utf8) else { throw Abort(.unauthorized) }
                do {
                    let jwt = try JWT<VerifiedToken<AccessTokenVerifier<Self>, AWSCognitoAccessToken>>(from: tokenData, verifiedUsing: signers)
                    return jwt.payload.payload
                } catch DecodingError.keyNotFound(let key, _) {
                    throw Abort(.unauthorized, reason: "This is not an access Token. Field '\(key.stringValue)' is missing")
                }
        }
    }
}

extension AWSCognitoAuthenticatable {
    /// load JSON web keys and create JWT signers from them
    static func loadSigners(region: Region, on worker: Worker) -> Future<JWTSigners> {
        // check we haven't already loaded the jwt signing key set
        guard Self.jwtSigners == nil else { return worker.future(Self.jwtSigners!)}
        
        let JWTSignersHost = "cognito-idp.\(region.rawValue).amazonaws.com"
        let JWTSignersURL = URL(string: "https://cognito-idp.\(region.rawValue).amazonaws.com/\(Self.userPoolId)/.well-known/jwks.json")!

        return HTTP.HTTPClient.connect(scheme: .https, hostname: JWTSignersHost, on: worker)
            .then { (client)->Future<HTTPResponse> in
                let request = HTTP.HTTPRequest(method: .GET, url: JWTSignersURL)
                return client.send(request)
            }
            .thenThrowing { response in
                if let data = response.body.data {
                    let jwks = try JSONDecoder().decode(JWKS.self, from: data)
                    Self.jwtSigners = try JWTSigners(jwks: jwks)
                    return Self.jwtSigners!
                }
                // shouldnt get here
                return JWTSigners()
        }
    }
}
