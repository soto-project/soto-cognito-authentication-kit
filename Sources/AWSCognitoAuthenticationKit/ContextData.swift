import CognitoIdentityProvider

/// Protocol for objects that encompass both an eventloop and context data to be used by Cognito
public protocol AWSCognitoContextData {
    var contextData: CognitoIdentityProvider.ContextDataType? { get }
}

