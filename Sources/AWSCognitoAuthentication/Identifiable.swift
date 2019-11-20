import CognitoIdentity
import NIO

/// Protocol that include the configuration setup for AWS Cognito Identity.
///
/// See [Cognito Identity Pools](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-identity.html)
/// documention for more information.
public protocol AWSCognitoIdentifiable {
    /// cognito identity pool id
    static var identityPoolId: String { get }
    /// identity provider
    static var identityProvider: String { get }
    /// Cognito Identity client
    static var cognitoIdentity: CognitoIdentity { get }
}

/// Protocol that includes the configuration setup for AWS Cognito Identity when using AWS Cognito user pools as the identity provider
public protocol AWSCognitoUserPoolIdentifiable: AWSCognitoIdentifiable, AWSCognitoAuthenticatable { }

/// extend AWSCognitoUserPoolIdentifiable to setup the identity provider for cognito user pool
public extension AWSCognitoUserPoolIdentifiable {
    /// identity provider
    static var identityProvider: String { return "cognito-idp.\(Self.region.rawValue).amazonaws.com/\(Self.userPoolId)" }
}

public extension AWSCognitoIdentifiable {
    
    /// Return an Cognito Identity identity id from an id token
    /// - parameters:
    ///     - idToken: Id token returned from authenticating a user
    ///     - on: Event loop request is running on.
    /// - returns:
    ///     Event Loop Future returning the identity id as a String
    static func getIdentityId(idToken: String, on eventLoop: EventLoop) -> EventLoopFuture<String> {
        let request = CognitoIdentity.GetIdInput(identityPoolId: Self.identityPoolId, logins: [Self.identityProvider : idToken])
        return Self.cognitoIdentity.getId(request)
            .flatMapErrorThrowing { error in
                throw translateError(error: error)
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
    static func getCredentialForIdentity(identityId: String, idToken: String, on eventLoop: EventLoop) -> EventLoopFuture<CognitoIdentity.Credentials> {
        let request = CognitoIdentity.GetCredentialsForIdentityInput(identityId: identityId, logins: [Self.identityProvider : idToken])
        return Self.cognitoIdentity.getCredentialsForIdentity(request)
            .flatMapErrorThrowing { error in
                throw translateError(error: error)
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
    static func translateError(error: Error) -> Error {
        switch error {
        case CognitoIdentityErrorType.notAuthorizedException(let message):
            return AWSCognitoError.unauthorized(reason: message)

        default:
            return error
        }
    }
}
