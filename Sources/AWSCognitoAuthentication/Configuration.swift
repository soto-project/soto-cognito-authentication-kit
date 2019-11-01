import AWSSDKSwiftCore
import CognitoIdentityProvider
import JWT

public protocol AWSCognitoConfiguration {
    static var userPoolId: String { get }
    static var clientId: String { get }
    static var clientSecret: String { get }
    static var cognitoIDP: CognitoIdentityProvider { get }
    static var region: Region { get }
    static var jwtSigners: JWTSigners? { get set }
}

public protocol AWSCognitoConfigurationReference {
    associatedtype Configuration: AWSCognitoConfiguration
}
