import AWSCognitoAuthenticationKit
import Vapor

/// extend Vapor Request to provide Cognito context
extension Request: AWSCognitoEventLoopWithContext {
    public var cognitoContextData: CognitoIdentityProvider.ContextDataType? {
        let host = headers["Host"].first ?? "localhost:8080"
        guard let remoteAddress = remoteAddress else { return nil }
        let ipAddress: String
        switch remoteAddress {
        case .v4(let address):
            ipAddress = address.host
        case .v6(let address):
            ipAddress = address.host
        default:
            return nil
        }

        //guard let ipAddress = req.http.remotePeer.hostname ?? req.http.channel?.remoteAddress?.description else { return nil }
        let httpHeaders = headers.map { CognitoIdentityProvider.HttpHeader(headerName: $0.name, headerValue: $0.value) }
        let contextData = CognitoIdentityProvider.ContextDataType(
            httpHeaders: httpHeaders,
            ipAddress: ipAddress,
            serverName: host,
            serverPath: url.path)
        return contextData
    }
}
