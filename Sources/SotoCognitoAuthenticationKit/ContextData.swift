import SotoCognitoIdentityProvider

/// Protocol for objects that contains context data to be used by Cognito
public protocol CognitoContextData {
    var contextData: CognitoIdentityProvider.ContextDataType? { get }
}

