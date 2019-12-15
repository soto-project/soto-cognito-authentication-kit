import AWSCognitoAuthenticationKit
import Vapor

public extension Request {
    
    var awsCognito: AWSCognito {
        .init(request: self)
    }
    
    struct AWSCognito {
        
        /// helper function that returns if request with bearer token is cognito access authenticated
        /// - returns:
        ///     An access token object that contains the user name and id
        public func authenticateAccess() -> EventLoopFuture<AWSCognitoAccessToken> {
            guard let bearer = request.headers.bearerAuthorization else {
                return request.eventLoop.makeFailedFuture(Abort(.unauthorized))
            }
            return request.application.awsCognito.authenticatable.authenticate(accessToken: bearer.token, on: request.eventLoop)
        }

        /// helper function that returns if request with bearer token is cognito id authenticated and returns contents in the payload type
        /// - returns:
        ///     The payload contained in the token. See `authenticate<Payload: Codable>(idToken:on:)` for more details
        public func authenticateId<Payload: Codable>() -> EventLoopFuture<Payload> {
            guard let bearer = request.headers.bearerAuthorization else {
                return request.eventLoop.makeFailedFuture(Abort(.unauthorized))
            }
            return request.application.awsCognito.authenticatable.authenticate(idToken: bearer.token, on: request.eventLoop)
        }

        /// helper function that returns refreshed access and id tokens given a request containing the refresh token as a  bearer token
        /// - returns:
        ///     The payload contained in the token. See `authenticate<Payload: Codable>(idToken:on:)` for more details
        public func refresh(username: String) -> EventLoopFuture<AWSCognitoAuthenticateResponse> {
            guard let bearer = request.headers.bearerAuthorization else {
                return request.eventLoop.makeFailedFuture(Abort(.unauthorized))
            }
            return request.application.awsCognito.authenticatable.refresh(username: username, refreshToken: bearer.token, with: request)
        }
        
        /// helper function that returns AWS credentials for a provided identity. The idToken is provided as a bearer token.
        /// If you have setup to use an AWSCognito User pool to identify users then the idToken is the idToken returned from the `authenticate` function
        /// - returns:
        ///     AWS credentials for signing request to AWS
        public func awsCredentials() -> EventLoopFuture<CognitoIdentity.Credentials> {
            guard let bearer = request.headers.bearerAuthorization else {
                return request.eventLoop.makeFailedFuture(Abort(.unauthorized))
            }
            let identifiable = request.application.awsCognito.identifiable
            return identifiable.getIdentityId(idToken: bearer.token, on: request.eventLoop)
                .flatMap { identity in
                    return identifiable.getCredentialForIdentity(identityId: identity, idToken: bearer.token, on: self.request.eventLoop)
            }
        }
        
        let request: Request
    }
}

/// extend Vapor Request to provide Cognito context
extension Request: AWSCognitoEventLoopWithContext {
    public var cognitoContextData: CognitoIdentityProvider.ContextDataType? {
        let host = headers["Host"].first ?? "localhost:8080"
        guard let remoteAddress = remoteAddress else { return nil }
        let ipAddress: String
        switch remoteAddress {
        case .v4(let address):
            ipAddress = address.host
        case .v6(let address):
            ipAddress = address.host
        default:
            return nil
        }

        //guard let ipAddress = req.http.remotePeer.hostname ?? req.http.channel?.remoteAddress?.description else { return nil }
        let httpHeaders = headers.map { CognitoIdentityProvider.HttpHeader(headerName: $0.name, headerValue: $0.value) }
        let contextData = CognitoIdentityProvider.ContextDataType(
            httpHeaders: httpHeaders,
            ipAddress: ipAddress,
            serverName: host,
            serverPath: url.path)
        return contextData
    }
}
