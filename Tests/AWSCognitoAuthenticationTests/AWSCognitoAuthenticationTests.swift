import XCTest
import AWSSDKSwiftCore
import OpenCrypto
import NIO
import Vapor
@testable import AWSCognitoAuthentication

func attempt(function : () throws -> ()) {
    do {
        try function()
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
class AWSCognitoEventLoopWithContextTest: AWSCognitoEventLoopWithContext {
    let eventLoop: EventLoop
    var cognitoContextData: CognitoIdentityProvider.ContextDataType? {
        return CognitoIdentityProvider.ContextDataType(httpHeaders: [], ipAddress: "127.0.0.1", serverName: "127.0.0.1", serverPath: "/")
    }
    
    init(_ eventLoop: EventLoop) {
        self.eventLoop = eventLoop
    }
}

final class AWSCognitoAuthenticationTests: XCTestCase, AWSCognitoAuthenticatable {
    static let userPoolName: String = "aws-cognito-authentication-tests"
    static let userPoolClientName: String = "aws-cognito-authentication-tests"
    
    // AWSCognitoAuthenticatable
    static var userPoolId: String = ""
    static var clientId: String = ""
    static var clientSecret: String = ""
    static let cognitoIDP = CognitoIdentityProvider(region: .useast1, eventLoopGroupProvider: .shared(MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)))
    static var region: Region = .useast1
    static var jwtSigners: JWTSigners? = nil
    
    
    class override func setUp() {
        do {
            // does userpool exist
            let listRequest = CognitoIdentityProvider.ListUserPoolsRequest(maxResults: 60)
            let userPools = try cognitoIDP.listUserPools(listRequest).wait().userPools
            if let userPool = userPools?.first(where: { $0.name == userPoolName }) {
                self.userPoolId = userPool.id!
            } else {
                // create userpool
                let createRequest = CognitoIdentityProvider.CreateUserPoolRequest(
                    adminCreateUserConfig: CognitoIdentityProvider.AdminCreateUserConfigType(allowAdminCreateUserOnly: true),
                    poolName: userPoolName)
                let createResponse = try cognitoIDP.createUserPool(createRequest).wait()
                self.userPoolId = createResponse.userPool!.id!
            }
            
            // does userpool client exist
            let listClientRequest = CognitoIdentityProvider.ListUserPoolClientsRequest(maxResults: 60, userPoolId: self.userPoolId)
            let clients = try cognitoIDP.listUserPoolClients(listClientRequest).wait().userPoolClients
            if let client = clients?.first(where: { $0.clientName == userPoolClientName }) {
                self.clientId = client.clientId!
                let describeRequest = CognitoIdentityProvider.DescribeUserPoolClientRequest(clientId: self.clientId, userPoolId: self.userPoolId)
                let describeResponse = try cognitoIDP.describeUserPoolClient(describeRequest).wait()
                self.clientSecret = describeResponse.userPoolClient!.clientSecret!
            } else {
                // create userpool client
                let createClientRequest = CognitoIdentityProvider.CreateUserPoolClientRequest(
                    clientName: userPoolClientName,
                    explicitAuthFlows: [.adminNoSrpAuth],
                    generateSecret: true,
                    userPoolId: self.userPoolId)
                let createClientResponse = try cognitoIDP.createUserPoolClient(createClientRequest).wait()
                self.clientId = createClientResponse.userPoolClient!.clientId!
                self.clientSecret = createClientResponse.userPoolClient!.clientSecret!
            }
        } catch {
            print(error.localizedDescription)
        }
    }
    
    class TestData {
        let username: String
        let password: String
        
        init(_ testName: String, attributes: [String: String] = [:], on eventloop: EventLoop) throws {
            self.username = testName
            let messageHmac: HashedAuthenticationCode<SHA256> = HMAC.authenticationCode(for: Data(testName.utf8), using: SymmetricKey(data: Data(AWSCognitoAuthenticationTests.clientSecret.utf8)))
            self.password = messageHmac.description + "1%A"
            
            let create = AWSCognitoAuthenticationTests.createUser(username: self.username, attributes: attributes, temporaryPassword: password, messageAction:.suppress, on: eventloop)
                .map { _ in return }
                // deal with user already existing
                .flatMapErrorThrowing { error in
                    if let error = error as? Abort {
                        if error.status == .conflict && error.reason == "Username already exists" {
                            return
                        }
                    }
                    throw error
            }
            _ = try create.wait()
        }
        
        deinit {
            
        }
    }
    
    func login(_ testData: TestData, on eventLoop: EventLoop) -> EventLoopFuture<AWSCognitoAuthenticateResponse> {
        let context = AWSCognitoEventLoopWithContextTest(eventLoop)
        return AWSCognitoAuthenticationTests.authenticate(username: testData.username, password: testData.password, with: context)
            .flatMap { response in
                if let challenged = response.challenged, let session = challenged.session {
                    if challenged.name == "NEW_PASSWORD_REQUIRED" {
                        return AWSCognitoAuthenticationTests.respondToChallenge(
                            username: testData.username,
                            name: .newPasswordRequired,
                            responses: ["NEW_PASSWORD": testData.password],
                            session: session,
                            with: context)
                    } else {
                        return eventLoop.makeFailedFuture(AWSCognitoTestError.unrecognisedChallenge)
                    }
                }
                return eventLoop.makeSucceededFuture(response)
        }
    }
    
    func testAccessToken() {
        attempt {
            let eventLoop = Self.cognitoIDP.client.eventLoopGroup.next()
            let testData = try TestData(#function, on: eventLoop)
            
            let result = try login(testData, on: eventLoop)
                .flatMap { (response)->EventLoopFuture<AWSCognitoAccessToken> in
                    guard let authenticated = response.authenticated else { return eventLoop.makeFailedFuture(AWSCognitoTestError.notAuthenticated) }
                    guard let accessToken = authenticated.accessToken else { return eventLoop.makeFailedFuture(AWSCognitoTestError.missingToken) }
                    
                    return AWSCognitoAuthenticationTests.authenticate(accessToken: accessToken, on: eventLoop)
            }.wait()
            XCTAssertEqual(result.username, testData.username)
        }
    }

    func testIdToken() {
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
                    guard let authenticated = response.authenticated else { return eventLoop.makeFailedFuture(AWSCognitoTestError.notAuthenticated) }
                    guard let idToken = authenticated.idToken else { return eventLoop.makeFailedFuture(AWSCognitoTestError.missingToken) }
                    
                    return AWSCognitoAuthenticationTests.authenticate(idToken: idToken, on: eventLoop)
            }.wait()
            XCTAssertEqual(result.email, attributes["email"])
            XCTAssertEqual(result.givenName, attributes["given_name"])
            XCTAssertEqual(result.familyName, attributes["family_name"])
            print(result)
        }
    }

    func testRefreshToken() {
        attempt {
            let eventLoop = Self.cognitoIDP.client.eventLoopGroup.next()
            let testData = try TestData(#function, on: eventLoop)
            
            let result = try login(testData, on: eventLoop)
                .flatMap { (response)->EventLoopFuture<AWSCognitoAuthenticateResponse> in
                    guard let authenticated = response.authenticated else { return eventLoop.makeFailedFuture(AWSCognitoTestError.notAuthenticated) }
                    guard let refreshToken = authenticated.refreshToken else { return eventLoop.makeFailedFuture(AWSCognitoTestError.missingToken) }
                    let context = AWSCognitoEventLoopWithContextTest(eventLoop)
                    
                    return AWSCognitoAuthenticationTests.refresh(username: testData.username, refreshToken: refreshToken, with: context)
                }
                .flatMap { (response)->EventLoopFuture<AWSCognitoAccessToken> in
                    guard let authenticated = response.authenticated else { return eventLoop.makeFailedFuture(AWSCognitoTestError.notAuthenticated) }
                    guard let accessToken = authenticated.accessToken else { return eventLoop.makeFailedFuture(AWSCognitoTestError.missingToken) }
                    
                    return AWSCognitoAuthenticationTests.authenticate(accessToken: accessToken, on: eventLoop)
            }.wait()
            print(result)
        }
    }
    
    static var allTests = [
        ("testAccessToken", testAccessToken),
    ]
}
