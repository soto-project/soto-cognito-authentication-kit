import CognitoIdentityProvider
import NIO

/// Protocol for objects that encompass both an eventloop and context data to be used by Cognito
public protocol AWSCognitoEventLoopWithContext {
    var eventLoop: EventLoop { get }
    var cognitoContextData: CognitoIdentityProvider.ContextDataType? { get }
}

