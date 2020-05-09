import AWSCognitoIdentityProvider

/// Protocol for objects that contains context data to be used by Cognito
public protocol AWSCognitoContextData {
    var contextData: CognitoIdentityProvider.ContextDataType? { get }
}

