import XCTest
import AWSSDKSwiftCore
import AWSCognitoIdentityProvider
import Crypto
import Foundation
import NIO
@testable import AWSCognitoAuthenticationKit

func attempt(function : () throws -> ()) {
    do {
        try function()
    } catch let error as AWSErrorType {
        XCTFail(error.description)
    } catch {
        XCTFail(error.localizedDescription)
    }
}

enum AWSCognitoTestError: Error {
    case unrecognisedChallenge
    case notAuthenticated
    case missingToken
}

/// eventLoop with context object used for tests
class AWSCognitoContextTest: AWSCognitoContextData {
    var contextData: CognitoIdentityProvider.ContextDataType? {
        return CognitoIdentityProvider.ContextDataType(httpHeaders: [], ipAddress: "127.0.0.1", serverName: "127.0.0.1", serverPath: "/")
    }
}

final class AWSCognitoAuthenticationKitTests: XCTestCase {

    static var middlewares: [AWSServiceMiddleware] {
        ProcessInfo.processInfo.environment["CI"] == "true" ? [] : [AWSLoggingMiddleware()]
    }
    static let awsClient = AWSClient(middlewares: middlewares, httpClientProvider: .createNew)
    static let cognitoIDP = CognitoIdentityProvider(client: awsClient, region: .useast1)
    static let userPoolName: String = "aws-cognito-authentication-tests"
    static let userPoolClientName: String = "aws-cognito-authentication-tests"
    static var authenticatable: AWSCognitoAuthenticatable!
    static var authenticatableUnauthenticated: AWSCognitoAuthenticatable!

    static var setUpFailure: String? = nil

    class override func setUp() {
        do {
            let userPoolId: String
            let clientId: String
            let clientSecret: String
            // does userpool exist
            let listRequest = CognitoIdentityProvider.ListUserPoolsRequest(maxResults: 60)
            let userPools = try cognitoIDP.listUserPools(listRequest).wait().userPools
            if let userPool = userPools?.first(where: { $0.name == userPoolName }) {
                userPoolId = userPool.id!
            } else {
                // create userpool
                let createRequest = CognitoIdentityProvider.CreateUserPoolRequest(
                    adminCreateUserConfig: CognitoIdentityProvider.AdminCreateUserConfigType(allowAdminCreateUserOnly: true),
                    poolName: userPoolName)
                let createResponse = try cognitoIDP.createUserPool(createRequest).wait()
                userPoolId = createResponse.userPool!.id!
            }

            // does userpool client exist
            let listClientRequest = CognitoIdentityProvider.ListUserPoolClientsRequest(maxResults: 60, userPoolId: userPoolId)
            let clients = try cognitoIDP.listUserPoolClients(listClientRequest).wait().userPoolClients
            if let client = clients?.first(where: { $0.clientName == userPoolClientName }) {
                clientId = client.clientId!
                let describeRequest = CognitoIdentityProvider.DescribeUserPoolClientRequest(clientId: clientId, userPoolId: userPoolId)
                let describeResponse = try cognitoIDP.describeUserPoolClient(describeRequest).wait()
                clientSecret = describeResponse.userPoolClient!.clientSecret!
            } else {
                // create userpool client
                let createClientRequest = CognitoIdentityProvider.CreateUserPoolClientRequest(
                    clientName: userPoolClientName,
                    explicitAuthFlows: [.adminNoSrpAuth],
                    generateSecret: true,
                    userPoolId: userPoolId)
                let createClientResponse = try cognitoIDP.createUserPoolClient(createClientRequest).wait()
                clientId = createClientResponse.userPoolClient!.clientId!
                clientSecret = createClientResponse.userPoolClient!.clientSecret!
            }
            let configuration = AWSCognitoConfiguration(
                userPoolId: userPoolId,
                clientId: clientId,
                clientSecret: clientSecret,
                cognitoIDP: self.cognitoIDP,
                region: .useast1)
            Self.authenticatable = AWSCognitoAuthenticatable(configuration: configuration)
        } catch let error as AWSErrorType {
            setUpFailure = error.description
        } catch {
            setUpFailure = error.localizedDescription
        }
    }

    class TestData {
        let username: String
        let password: String

        init(_ testName: String, attributes: [String: String] = [:], on eventloop: EventLoop) throws {
            self.username = testName
            let messageHmac: HashedAuthenticationCode<SHA256> = HMAC.authenticationCode(for: Data(testName.utf8), using: SymmetricKey(data: Data(AWSCognitoAuthenticationKitTests.authenticatable.configuration.clientSecret.utf8)))
            self.password = messageHmac.description + "1!A"

            let create = AWSCognitoAuthenticationKitTests.authenticatable.createUser(username: self.username, attributes: attributes, temporaryPassword: password, messageAction:.suppress, on: eventloop)
                .map { _ in return }
                // deal with user already existing
                .flatMapErrorThrowing { error in
                    if case CognitoIdentityProviderErrorType.usernameExistsException(_) = error {
                        return
                    }
                    throw error
            }
            _ = try create.wait()
        }

        deinit {
            let deleteUserRequest = CognitoIdentityProvider.AdminDeleteUserRequest(username: username, userPoolId: AWSCognitoAuthenticationKitTests.authenticatable.configuration.userPoolId)
            try? AWSCognitoAuthenticationKitTests.cognitoIDP.adminDeleteUser(deleteUserRequest).wait()
        }
    }

    func login(_ testData: TestData, on eventLoop: EventLoop) -> EventLoopFuture<AWSCognitoAuthenticateResponse> {
        let context = AWSCognitoContextTest()
        return Self.authenticatable.authenticate(username: testData.username, password: testData.password, context: context, on: eventLoop)
            .flatMap { response in
                if case .challenged(let challenged) = response, let session = challenged.session {
                    if challenged.name == "NEW_PASSWORD_REQUIRED" {
                        return Self.authenticatable.respondToChallenge(
                            username: testData.username,
                            name: .newPasswordRequired,
                            responses: ["NEW_PASSWORD": testData.password],
                            session: session,
                            context: context,
                            on: eventLoop)
                    } else {
                        return eventLoop.makeFailedFuture(AWSCognitoTestError.unrecognisedChallenge)
                    }
                }
                return eventLoop.makeSucceededFuture(response)
        }
    }

    func testAccessToken() {
        XCTAssertNil(Self.setUpFailure)
        attempt {
            let eventLoop = Self.cognitoIDP.client.eventLoopGroup.next()
            let testData = try TestData(#function, on: eventLoop)

            let result = try login(testData, on: eventLoop)
                .flatMap { (response)->EventLoopFuture<AWSCognitoAccessToken> in
                    guard case .authenticated(let authenticated) = response else { return eventLoop.makeFailedFuture(AWSCognitoTestError.notAuthenticated) }
                    guard let accessToken = authenticated.accessToken else { return eventLoop.makeFailedFuture(AWSCognitoTestError.missingToken) }

                    return Self.authenticatable.authenticate(accessToken: accessToken, on: eventLoop)
            }.wait()
            XCTAssertEqual(result.username, testData.username)
        }
    }

    func testIdToken() {
        XCTAssertNil(Self.setUpFailure)
        struct User: Codable {
            let email: String
            let givenName: String
            let familyName: String

            private enum CodingKeys: String, CodingKey {
                case email = "email"
                case givenName = "given_name"
                case familyName = "family_name"
            }
        }

        attempt {
            let eventLoop = Self.cognitoIDP.client.eventLoopGroup.next()
            let attributes = ["given_name": "John", "family_name": "Smith", "email": "johnsmith@email.com"]
            let testData = try TestData(#function, attributes: attributes, on: eventLoop)

            let result = try login(testData, on: eventLoop)
                .flatMap { (response)->EventLoopFuture<User> in
                    guard case .authenticated(let authenticated) = response else { return eventLoop.makeFailedFuture(AWSCognitoTestError.notAuthenticated) }
                    guard let idToken = authenticated.idToken else { return eventLoop.makeFailedFuture(AWSCognitoTestError.missingToken) }

                    return Self.authenticatable.authenticate(idToken: idToken, on: eventLoop)
            }.wait()
            XCTAssertEqual(result.email, attributes["email"])
            XCTAssertEqual(result.givenName, attributes["given_name"])
            XCTAssertEqual(result.familyName, attributes["family_name"])
            print(result)
        }
    }

    func testRefreshToken() {
        XCTAssertNil(Self.setUpFailure)
        attempt {
            let eventLoop = Self.cognitoIDP.client.eventLoopGroup.next()
            let testData = try TestData(#function, on: eventLoop)

            let result = try login(testData, on: eventLoop)
                .flatMap { (response)->EventLoopFuture<AWSCognitoAuthenticateResponse> in
                    guard case .authenticated(let authenticated) = response else { return eventLoop.makeFailedFuture(AWSCognitoTestError.notAuthenticated) }
                    guard let refreshToken = authenticated.refreshToken else { return eventLoop.makeFailedFuture(AWSCognitoTestError.missingToken) }
                    let context = AWSCognitoContextTest()

                    return Self.authenticatable.refresh(username: testData.username, refreshToken: refreshToken, context: context, on: eventLoop)
                }
                .flatMap { (response)->EventLoopFuture<AWSCognitoAccessToken> in
                    guard case .authenticated(let authenticated) = response else { return eventLoop.makeFailedFuture(AWSCognitoTestError.notAuthenticated) }
                    guard let accessToken = authenticated.accessToken else { return eventLoop.makeFailedFuture(AWSCognitoTestError.missingToken) }

                    return Self.authenticatable.authenticate(accessToken: accessToken, on: eventLoop)
            }.wait()
            print(result)
        }
    }


    static var allTests = [
        ("testAccessToken", testAccessToken),
        ("testIdToken", testIdToken),
        ("testRefreshToken", testRefreshToken),
    ]
}
