import AWSSDKSwiftCore
import CognitoIdentity
import CognitoIdentityProvider
import JWT

/// Protocol for storing configuration for accessing a AWS Cognito user pool
public protocol AWSCognitoConfiguration {
    /// user pool id
    static var userPoolId: String { get }
    /// app client it
    static var clientId: String { get }
    /// app client secret
    static var clientSecret: String { get }
    /// Cognito Identity Provider client
    static var cognitoIDP: CognitoIdentityProvider { get }
    /// region userpool is in
    static var region: Region { get }
    /// Json web token signers
    static var jwtSigners: JWTSigners? { get set }

    /// cognito identity pool id
    static var identityPoolId: String? { get }
    /// Cognito Identity client
    static var cognitoIdentity: CognitoIdentity? { get }
}

public extension AWSCognitoConfiguration {
    static var identityPoolId: String? { return nil }
    static var cognitoIdentity: CognitoIdentity? {return nil}
}
