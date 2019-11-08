import CognitoIdentity
import NIO
import Vapor

enum AWSCognitoIdentityError: Error {
    case noIdentityPoolId
    case noIdentityClient
}

public extension AWSCognitoAuthenticatable {
    
    /// return an identity id from an id token
    static func getIdentityId(idToken: String, on worker: Worker) -> EventLoopFuture<String> {
        guard let identityPoolId = Self.identityPoolId else { return worker.next().newFailedFuture(error: AWSCognitoIdentityError.noIdentityPoolId) }
        guard let client = Self.cognitoIdentity else { return worker.next().newFailedFuture(error: AWSCognitoIdentityError.noIdentityClient) }
        let provider = "cognito-idp.\(Self.region.rawValue).amazonaws.com/\(Self.userPoolId)"
        let request = CognitoIdentity.GetIdInput(identityPoolId: identityPoolId, logins: [provider : idToken])
        return client.getId(request)
            .thenIfErrorThrowing { error in
                throw translateError(error: error)
            }
            .thenThrowing { response in
                guard let identityId = response.identityId else { throw Abort(.internalServerError) }
                return identityId
            }
            .hopTo(eventLoop: worker.eventLoop)
    }
    
    /// get aws credentials from an identity id
    static func getCredentialForIdentity(identityId: String, idToken: String, on worker: Worker) -> EventLoopFuture<CognitoIdentity.Credentials> {
        guard let client = Self.cognitoIdentity else { return worker.next().newFailedFuture(error: AWSCognitoIdentityError.noIdentityClient) }
        let provider = "cognito-idp.\(Self.region.rawValue).amazonaws.com/\(Self.userPoolId)"

        let request = CognitoIdentity.GetCredentialsForIdentityInput(identityId: identityId, logins: [provider : idToken])
        return client.getCredentialsForIdentity(request)
            .thenIfErrorThrowing { error in
                throw translateError(error: error)
            }
            .thenThrowing { response in
                guard let credentials = response.credentials else { throw Abort(.internalServerError) }
                return credentials
            }
            .hopTo(eventLoop: worker.eventLoop)
    }
}
