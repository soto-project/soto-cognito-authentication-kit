import CognitoIdentity
import NIO
import Vapor

enum AWSCognitoIdentityError: Error {
    case noIdentityPoolId
    case noIdentityClient
}

/// Protocol that include the configuration setup for AWS Cognito Identity.
///
/// If you are using CognitoIdentity you are required to provide setup for CognitoIdentityProvider as well
public protocol AWSCognitoIdentifiable: AWSCognitoAuthenticatable {
    /// cognito identity pool id
    static var identityPoolId: String { get }
    /// Cognito Identity client
    static var cognitoIdentity: CognitoIdentity { get }
}

public extension AWSCognitoIdentifiable {
    
    /// return an identity id from an id token
    static func getIdentityId(idToken: String, on eventLoopGroup: EventLoopGroup) -> EventLoopFuture<String> {
        let provider = "cognito-idp.\(Self.region.rawValue).amazonaws.com/\(Self.userPoolId)"
        let request = CognitoIdentity.GetIdInput(identityPoolId: Self.identityPoolId, logins: [provider : idToken])
        return Self.cognitoIdentity.getId(request)
            .flatMapErrorThrowing { error in
                throw translateError(error: error)
            }
            .flatMapThrowing { response in
                guard let identityId = response.identityId else { throw Abort(.internalServerError) }
                return identityId
            }
            .hop(to: eventLoopGroup.next())
    }
    
    /// get aws credentials from an identity id
    static func getCredentialForIdentity(identityId: String, idToken: String, on eventLoopGroup: EventLoopGroup) -> EventLoopFuture<CognitoIdentity.Credentials> {
        let provider = "cognito-idp.\(Self.region.rawValue).amazonaws.com/\(Self.userPoolId)"
        let request = CognitoIdentity.GetCredentialsForIdentityInput(identityId: identityId, logins: [provider : idToken])
        return Self.cognitoIdentity.getCredentialsForIdentity(request)
            .flatMapErrorThrowing { error in
                throw translateError(error: error)
            }
            .flatMapThrowing { response in
                guard let credentials = response.credentials else { throw Abort(.internalServerError) }
                return credentials
            }
        .hop(to: eventLoopGroup.next())
    }
}

extension AWSCognitoIdentifiable {
    /// translate error from one thrown by aws-sdk-swift to vapor error
    static func translateError(error: Error) -> Error {
        switch error {
        case CognitoIdentityErrorType.notAuthorizedException(let message):
            return Abort(.unauthorized, reason: message)

        default:
            return error
        }
    }
}
