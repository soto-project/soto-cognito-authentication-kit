import AWSCognitoIdentity
import NIO

public class AWSCognitoIdentifiable {
    
    /// configuration
    public let configuration: AWSCognitoIdentityConfiguration
    
    public init(configuration: AWSCognitoIdentityConfiguration) {
        self.configuration = configuration
    }
    
    /// Return an Cognito Identity identity id from an id token
    /// - parameters:
    ///     - idToken: Id token returned from authenticating a user
    ///     - on: Event loop request is running on.
    /// - returns:
    ///     Event Loop Future returning the identity id as a String
    public func getIdentityId(idToken: String, on eventLoop: EventLoop) -> EventLoopFuture<String> {
        let request = CognitoIdentity.GetIdInput(identityPoolId: configuration.identityPoolId, logins: [configuration.identityProvider : idToken])
        return configuration.cognitoIdentity.getId(request)
            .flatMapErrorThrowing { error in
                throw self.translateError(error: error)
            }
            .flatMapThrowing { response in
                guard let identityId = response.identityId else { throw AWSCognitoError.unexpectedResult(reason: "AWS did not return an identity id") }
                return identityId
            }
            .hop(to: eventLoop)
    }
    
    /// Get aws credentials from an identity id
    /// - parameters:
    ///     - identityId: Identity id returned from `getIdentityId`
    ///     - idToken: Id token returned from authenticating a user
    ///     - on: Event loop request is running on.
    /// - returns:
    ///     Event loop future returning AWS credentials
    public func getCredentialForIdentity(identityId: String, idToken: String, on eventLoop: EventLoop) -> EventLoopFuture<CognitoIdentity.Credentials> {
        let request = CognitoIdentity.GetCredentialsForIdentityInput(identityId: identityId, logins: [configuration.identityProvider : idToken])
        return configuration.cognitoIdentity.getCredentialsForIdentity(request)
            .flatMapErrorThrowing { error in
                throw self.translateError(error: error)
            }
            .flatMapThrowing { response in
                guard let credentials = response.credentials else { throw AWSCognitoError.unexpectedResult(reason: "AWS did not supply any credentials") }
                return credentials
            }
        .hop(to: eventLoop)
    }
}

extension AWSCognitoIdentifiable {
    /// translate error from one thrown by aws-sdk-swift to vapor error
    func translateError(error: Error) -> Error {
        switch error {
        case CognitoIdentityErrorType.notAuthorizedException(let message):
            return AWSCognitoError.unauthorized(reason: message)

        default:
            return error
        }
    }
}
