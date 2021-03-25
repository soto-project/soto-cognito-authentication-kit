//===----------------------------------------------------------------------===//
//
// This source file is part of the Soto for AWS open source project
//
// Copyright (c) 2020-2021 the Soto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of Soto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import XCTest
import AsyncHTTPClient
import SotoCore
import SotoCognitoIdentity
import SotoCognitoIdentityProvider
import Crypto
import Foundation
import NIO
@testable import SotoCognitoAuthenticationKit

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
class AWSCognitoContextTest: CognitoContextData {
    var contextData: CognitoIdentityProvider.ContextDataType? {
        return CognitoIdentityProvider.ContextDataType(httpHeaders: [], ipAddress: "127.0.0.1", serverName: "127.0.0.1", serverPath: "/")
    }
}

final class SotoCognitoAuthenticationKitTests: XCTestCase {

    static var middlewares: [AWSServiceMiddleware] {
        ProcessInfo.processInfo.environment["CI"] == "true" ? [] : [AWSLoggingMiddleware()]
    }
    static var awsClient: AWSClient!
    static var region: Region = .useast1
    static var cognitoIdentity: CognitoIdentity!
    static var cognitoIDP: CognitoIdentityProvider!
    static let userPoolName: String = "aws-cognito-authentication-tests"
    static let userPoolClientName: String = UUID().uuidString
    static var authenticatable: CognitoAuthenticatable!
    static var userPoolId: String!
    static var clientId: String!
    static var clientSecret: String!
    static let identityPoolName: String = UUID().uuidString
    static var identityPoolId: String!
    static var identifiable: CognitoIdentifiable!

    static var setUpFailure: String? = nil

    class override func setUp() {
        awsClient = AWSClient(middlewares: Self.middlewares, httpClientProvider: .createNew)
        cognitoIDP = CognitoIdentityProvider(client: awsClient, region: region)
        cognitoIdentity = CognitoIdentity(client: awsClient, region: region)
        do {
            try setupUserpool()
            
            let configuration = CognitoConfiguration(
                userPoolId: userPoolId,
                clientId: clientId,
                clientSecret: clientSecret,
                cognitoIDP: self.cognitoIDP
            )
            Self.authenticatable = CognitoAuthenticatable(configuration: configuration)
            
            try setupIdentityPool()

            let identityConfiguration = CognitoIdentityConfiguration(
                identityPoolId: Self.identityPoolId,
                userPoolId: Self.userPoolId,
                region: Self.region,
                cognitoIdentity: Self.cognitoIdentity
            )
            Self.identifiable = CognitoIdentifiable(configuration: identityConfiguration)
        } catch let error as AWSErrorType {
            setUpFailure = error.description
        } catch {
            setUpFailure = error.localizedDescription
        }
    }

    class override func tearDown() {
        // delete client so we need to re-generate
        let deleteClientRequest = CognitoIdentityProvider.DeleteUserPoolClientRequest(clientId: Self.clientId, userPoolId: Self.userPoolId)
        XCTAssertNoThrow(try cognitoIDP.deleteUserPoolClient(deleteClientRequest).wait())
        let deleteIdentityPool = CognitoIdentity.DeleteIdentityPoolInput(identityPoolId: Self.identityPoolId)
        XCTAssertNoThrow(try cognitoIdentity.deleteIdentityPool(deleteIdentityPool).wait())
        XCTAssertNoThrow(try awsClient.syncShutdown())
    }

    class TestData {
        let username: String
        let password: String

        init(_ testName: String, attributes: [String: String] = [:], on eventloop: EventLoop) throws {
            self.username = testName + Self.randomString()
            let messageHmac: HashedAuthenticationCode<SHA256> = HMAC.authenticationCode(
                for: Data(testName.utf8),
                using: SymmetricKey(data: Data(SotoCognitoAuthenticationKitTests.authenticatable.configuration.userPoolId.utf8))
            )
            self.password = messageHmac.description + "1!A"

            let create = SotoCognitoAuthenticationKitTests.authenticatable.createUser(username: self.username, attributes: attributes, temporaryPassword: password, messageAction:.suppress, on: eventloop)
                .map { _ in return }
                // deal with user already existing
                .flatMapErrorThrowing { error in
                    if let error = error as? CognitoIdentityProviderErrorType, error == .usernameExistsException {
                        return
                    }
                    throw error
            }
            _ = try create.wait()
        }

        deinit {
            let deleteUserRequest = CognitoIdentityProvider.AdminDeleteUserRequest(username: username, userPoolId: SotoCognitoAuthenticationKitTests.authenticatable.configuration.userPoolId)
            try? SotoCognitoAuthenticationKitTests.cognitoIDP.adminDeleteUser(deleteUserRequest).wait()
        }

        static func randomString() -> String {
            return String((0...7).map { _ in ("abcdefghijklmnopqrstuvwxyz").randomElement()! })
        }
    }

    static func setupUserpool() throws {
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
            clientSecret = describeResponse.userPoolClient!.clientSecret
        } else {
            // create userpool client
            let createClientRequest = CognitoIdentityProvider.CreateUserPoolClientRequest(
                clientName: userPoolClientName,
                explicitAuthFlows: [.allowAdminUserPasswordAuth, .allowUserPasswordAuth, .allowRefreshTokenAuth],
                generateSecret: true,
                userPoolId: userPoolId)
            let createClientResponse = try cognitoIDP.createUserPoolClient(createClientRequest).wait()
            clientId = createClientResponse.userPoolClient!.clientId!
            clientSecret = createClientResponse.userPoolClient!.clientSecret
        }
    }
    
    static func setupIdentityPool() throws {
        // create identity pool
        let providerName = "cognito-idp.\(Self.region.rawValue).amazonaws.com/\(Self.userPoolId!)"
        let createRequest = CognitoIdentity.CreateIdentityPoolInput(
            allowUnauthenticatedIdentities: false,
            cognitoIdentityProviders: [.init(clientId: Self.clientId, providerName: providerName)],
            identityPoolName: identityPoolName
        )
        let createResponse = try cognitoIdentity.createIdentityPool(createRequest).wait()
        Self.identityPoolId = createResponse.identityPoolId
    }
    
    func login(_ testData: TestData, authenticatable: CognitoAuthenticatable, requireAuthenticatedClient: Bool = true, on eventLoop: EventLoop) -> EventLoopFuture<CognitoAuthenticateResponse> {
        let context = AWSCognitoContextTest()
        return authenticatable.authenticate(
            username: testData.username,
            password: testData.password,
            requireAuthenticatedClient: requireAuthenticatedClient,
            context: context,
            on: eventLoop
        ).flatMap { response in
            if case .challenged(let challenged) = response, let session = challenged.session {
                if challenged.name == "NEW_PASSWORD_REQUIRED" {
                    return authenticatable.respondToNewPasswordChallenge(
                        username: testData.username,
                        password: testData.password,
                        session: session,
                        requireAuthenticatedClient: requireAuthenticatedClient,
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

            let result = try login(testData, authenticatable: Self.authenticatable, on: eventLoop)
                .flatMap { (response)->EventLoopFuture<CognitoAccessToken> in
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

            let result = try login(testData, authenticatable: Self.authenticatable, on: eventLoop)
                .flatMap { (response)->EventLoopFuture<User> in
                    guard case .authenticated(let authenticated) = response else { return eventLoop.makeFailedFuture(AWSCognitoTestError.notAuthenticated) }
                    guard let idToken = authenticated.idToken else { return eventLoop.makeFailedFuture(AWSCognitoTestError.missingToken) }

                    return Self.authenticatable.authenticate(idToken: idToken, on: eventLoop)
            }.wait()
            XCTAssertEqual(result.email, attributes["email"])
            XCTAssertEqual(result.givenName, attributes["given_name"])
            XCTAssertEqual(result.familyName, attributes["family_name"])
        }
    }

    func testRefreshToken() {
        XCTAssertNil(Self.setUpFailure)
        attempt {
            let eventLoop = Self.cognitoIDP.client.eventLoopGroup.next()
            let testData = try TestData(#function, on: eventLoop)

            _ = try login(testData, authenticatable: Self.authenticatable, on: eventLoop)
                .flatMap { (response)->EventLoopFuture<CognitoAuthenticateResponse> in
                    guard case .authenticated(let authenticated) = response else { return eventLoop.makeFailedFuture(AWSCognitoTestError.notAuthenticated) }
                    guard let refreshToken = authenticated.refreshToken else { return eventLoop.makeFailedFuture(AWSCognitoTestError.missingToken) }
                    let context = AWSCognitoContextTest()

                    return Self.authenticatable.refresh(username: testData.username, refreshToken: refreshToken, context: context, on: eventLoop)
                }
                .flatMap { (response)->EventLoopFuture<CognitoAccessToken> in
                    guard case .authenticated(let authenticated) = response else { return eventLoop.makeFailedFuture(AWSCognitoTestError.notAuthenticated) }
                    guard let accessToken = authenticated.accessToken else { return eventLoop.makeFailedFuture(AWSCognitoTestError.missingToken) }

                    return Self.authenticatable.authenticate(accessToken: accessToken, on: eventLoop)
            }.wait()
        }
    }

    func testUnauthenticatdClient() {
        XCTAssertNil(Self.setUpFailure)
        attempt {
            let awsClient = AWSClient(credentialProvider: .empty, httpClientProvider: .shared(Self.awsClient.httpClient))
            defer { XCTAssertNoThrow(try awsClient.syncShutdown()) }
            let cognitoIdentityProvider = CognitoIdentityProvider(client: awsClient, region: Self.cognitoIDP.region)
            let configuration = CognitoConfiguration(
                userPoolId: Self.authenticatable.configuration.userPoolId,
                clientId: Self.authenticatable.configuration.clientId,
                clientSecret: Self.authenticatable.configuration.clientSecret,
                cognitoIDP: cognitoIdentityProvider
            )
            let authenticatable = CognitoAuthenticatable(configuration: configuration)
            let eventLoop = cognitoIdentityProvider.client.eventLoopGroup.next()
            let testData = try TestData(#function, on: eventLoop)

            let result = try login(testData, authenticatable: authenticatable, requireAuthenticatedClient: false, on: eventLoop)
                .flatMap { (response)->EventLoopFuture<CognitoAccessToken> in
                    guard case .authenticated(let authenticated) = response else { return eventLoop.makeFailedFuture(AWSCognitoTestError.notAuthenticated) }
                    guard let accessToken = authenticated.accessToken else { return eventLoop.makeFailedFuture(AWSCognitoTestError.missingToken) }

                    return authenticatable.authenticate(accessToken: accessToken, on: eventLoop)
            }.wait()
            XCTAssertEqual(result.username, testData.username)
        }
    }


    func testRequireAuthenticatedClient() {
        XCTAssertNil(Self.setUpFailure)
        attempt {
            let awsClient = AWSClient(credentialProvider: .empty, httpClientProvider: .shared(Self.awsClient.httpClient))
            defer { XCTAssertNoThrow(try awsClient.syncShutdown()) }
            let cognitoIdentityProvider = CognitoIdentityProvider(client: awsClient, region: Self.cognitoIDP.region)
            let configuration = CognitoConfiguration(
                userPoolId: Self.authenticatable.configuration.userPoolId,
                clientId: Self.authenticatable.configuration.clientId,
                clientSecret: Self.authenticatable.configuration.clientSecret,
                cognitoIDP: cognitoIdentityProvider
            )
            let authenticatable = CognitoAuthenticatable(configuration: configuration)
            let eventLoop = cognitoIdentityProvider.client.eventLoopGroup.next()
            let testData = try TestData(#function, on: eventLoop)

            XCTAssertThrowsError(try login(testData, authenticatable: authenticatable, requireAuthenticatedClient: true, on: eventLoop).wait()) { error in
                switch error {
                case SotoCognitoError.unauthorized:
                    break
                default:
                    XCTFail("\(error)")
                }
            }
        }
    }

    func testAuthenticatedResponseCodable() throws {
        do {
            let authenticated = CognitoAuthenticateResponse.AuthenticatedResponse(
                accessToken: "ACCESSTOKEN",
                idToken: "IDTOKEN",
                refreshToken: "REFRESHTOKEN",
                expiresIn: nil
            )
            let response: CognitoAuthenticateResponse = .authenticated(authenticated)
            let data = try JSONEncoder().encode(response)
            let decoded = try JSONDecoder().decode(CognitoAuthenticateResponse.self, from: data)
            if case .authenticated(let decodedAuthenticated) = decoded {
                XCTAssertEqual(decodedAuthenticated.accessToken, authenticated.accessToken)
                XCTAssertEqual(decodedAuthenticated.idToken, authenticated.idToken)
                XCTAssertEqual(decodedAuthenticated.refreshToken, authenticated.refreshToken)
            } else {
                XCTFail()
            }
        }
        do {
            let challenged = CognitoAuthenticateResponse.ChallengedResponse(name: "NEW_PASSWORD_REQUIRED", parameters: ["USERNAME": "JohnDoe"], session: "SessionId")
            let response: CognitoAuthenticateResponse = .challenged(challenged)
            let data = try JSONEncoder().encode(response)
            let decoded = try JSONDecoder().decode(CognitoAuthenticateResponse.self, from: data)
            if case .challenged(let decodedChallenged) = decoded {
                XCTAssertEqual(decodedChallenged.name, challenged.name)
                XCTAssertEqual(decodedChallenged.parameters, challenged.parameters)
                XCTAssertEqual(decodedChallenged.session, challenged.session)
            } else {
                XCTFail()
            }
        }
    }

    func testAuthenticateFail() {
        XCTAssertNil(Self.setUpFailure)
        attempt {
            let eventLoop = Self.cognitoIDP.client.eventLoopGroup.next()
            let testData = try TestData(#function, on: eventLoop)
            let context = AWSCognitoContextTest()
            XCTAssertThrowsError(try Self.authenticatable.authenticate(
                username: testData.username,
                password: testData.password+"!",
                context: context,
                on: eventLoop
            ).wait()) { error in
                switch error {
                case SotoCognitoError.unauthorized:
                    break
                default:
                    XCTFail("\(error)")
                }
            }
        }
    }
    
    func testIdentity() {
        XCTAssertNil(Self.setUpFailure)
        attempt {
            let eventLoop = Self.cognitoIDP.client.eventLoopGroup.next()
            let testData = try TestData(#function, on: eventLoop)
            let result = login(testData, authenticatable: Self.authenticatable, on: eventLoop)
                .flatMap { (response)->EventLoopFuture<(String, String)> in
                    guard case .authenticated(let authenticated) = response else { return eventLoop.makeFailedFuture(AWSCognitoTestError.notAuthenticated) }
                    guard let idToken = authenticated.idToken else { return eventLoop.makeFailedFuture(AWSCognitoTestError.missingToken) }

                    return Self.identifiable.getIdentityId(idToken: idToken, on: eventLoop).map { id in (id, idToken)}
                }.flatMap { (id, idToken) -> EventLoopFuture<CognitoIdentity.Credentials> in
                    return Self.identifiable.getCredentialForIdentity(identityId: id, idToken: idToken, on: eventLoop)
                }
            XCTAssertThrowsError(try result.wait()) { error in
                switch error {
                // should get an invalid identity pool configuration error as the identity pool authentication provider
                // is setup as cognito userpools, but we havent set up a role to return
                case let error as CognitoIdentityErrorType where error == .invalidIdentityPoolConfigurationException:
                    break
                default:
                    XCTFail("\(error)")
                }
            }
        }
    }
}
