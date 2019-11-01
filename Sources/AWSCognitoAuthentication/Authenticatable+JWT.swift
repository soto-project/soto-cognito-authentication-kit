import AWSSDKSwiftCore
import JWT
import Vapor

public extension AWSCognitoAuthenticatable {
    /// verify IdToken JWT and return contents
    static func authenticateIdToken<Payload: Codable>(bearer: BearerAuthorization, on worker: Worker) -> Future<Payload> {
        return loadSigners(region: .euwest1, on: worker)
            .thenThrowing { signers in
                let jwt = try JWT<VerifiedToken<IdToken<Self>, Payload>>(from: bearer.token.data(using: .utf8)!, verifiedUsing: signers)
                return jwt.payload.payload
        }
    }

    /// verify AccessToken JWT and return contents
    static func authenticateAccessToken<Payload: Codable>(bearer: BearerAuthorization, on worker: Worker) -> Future<Payload> {
        return loadSigners(region: .euwest1, on: worker)
            .thenThrowing { signers in
                let jwt = try JWT<VerifiedToken<AccessToken<Self>, Payload>>(from: bearer.token.data(using: .utf8)!, verifiedUsing: signers)
                return jwt.payload.payload
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
