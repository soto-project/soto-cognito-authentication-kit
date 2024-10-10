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

import AsyncHTTPClient
import Crypto
import Foundation
import NIO
@testable import SotoCognitoAuthenticationKit
import SotoCognitoIdentity
import SotoCognitoIdentityProvider
import SotoCore
import XCTest

public func XCTRunAsyncAndBlock(_ closure: @Sendable @escaping () async throws -> Void) {
    let dg = DispatchGroup()
    dg.enter()
    Task {
        do {
            try await closure()
        } catch {
            XCTFail("\(error)")
        }
        dg.leave()
    }
    dg.wait()
}

enum AWSCognitoTestError: Error {
    case unrecognisedChallenge
    case notAuthenticated
    case missingToken
}

/// context object used for tests
struct AWSCognitoContextTest: CognitoContextData {
    var contextData: CognitoIdentityProvider.ContextDataType? {
        return CognitoIdentityProvider.ContextDataType(httpHeaders: [], ipAddress: "127.0.0.1", serverName: "127.0.0.1", serverPath: "/")
    }
}

final class CognitoTests: XCTestCase {
    var middleware: AWSMiddlewareProtocol? {
        ProcessInfo.processInfo.environment["CI"] == "true" ? nil : AWSLoggingMiddleware()
    }

    var awsClient: AWSClient!
    var region: Region = .useast1
    var cognitoIdentity: CognitoIdentity!
    var cognitoIDP: CognitoIdentityProvider!
    let userPoolName: String = "aws-cognito-authentication-tests"
    let userPoolClientName: String = UUID().uuidString
    var authenticatable: CognitoAuthenticatable!
    var userPoolId: String!
    var clientId: String!
    var clientSecret: String!
    let identityPoolName: String = UUID().uuidString
    var identityPoolId: String!
    var identifiable: CognitoIdentifiable!

    var setUpFailure: String?

    override func setUp() async throws {
        if ProcessInfo.processInfo.environment["CI"] == "true" {
            self.awsClient = AWSClient()
        } else {
            self.awsClient = AWSClient(middleware: AWSLoggingMiddleware())
        }

        self.cognitoIDP = CognitoIdentityProvider(client: self.awsClient, region: self.region)
        self.cognitoIdentity = CognitoIdentity(client: self.awsClient, region: self.region)
        do {
            try await self.setupUserpool()

            let configuration = CognitoConfiguration(
                userPoolId: userPoolId,
                clientId: clientId,
                clientSecret: clientSecret,
                cognitoIDP: self.cognitoIDP,
                adminClient: true
            )
            self.authenticatable = CognitoAuthenticatable(configuration: configuration)

            try await self.setupIdentityPool()

            let identityConfiguration = CognitoIdentityConfiguration(
                identityPoolId: self.identityPoolId,
                userPoolId: self.userPoolId,
                region: self.region,
                cognitoIdentity: self.cognitoIdentity
            )
            self.identifiable = CognitoIdentifiable(configuration: identityConfiguration)
        } catch let error as AWSErrorType {
            setUpFailure = error.description
        } catch {
            self.setUpFailure = error.localizedDescription
        }
    }

    override func tearDown() async throws {
        // delete client so we need to re-generate
        let deleteClientRequest = CognitoIdentityProvider.DeleteUserPoolClientRequest(clientId: self.clientId, userPoolId: self.userPoolId)
        try await self.cognitoIDP.deleteUserPoolClient(deleteClientRequest)
        let deleteIdentityPool = CognitoIdentity.DeleteIdentityPoolInput(identityPoolId: self.identityPoolId)
        try await self.cognitoIdentity.deleteIdentityPool(deleteIdentityPool)
        try await self.awsClient.shutdown()
    }

    func setupUserpool() async throws {
        // does userpool exist
        let listRequest = CognitoIdentityProvider.ListUserPoolsRequest(maxResults: 60)
        let userPools = try await cognitoIDP.listUserPools(listRequest).userPools
        if let userPool = userPools?.first(where: { $0.name == userPoolName }) {
            self.userPoolId = userPool.id!
        } else {
            // create userpool
            let createRequest = CognitoIdentityProvider.CreateUserPoolRequest(
                adminCreateUserConfig: CognitoIdentityProvider.AdminCreateUserConfigType(allowAdminCreateUserOnly: true),
                poolName: self.userPoolName
            )
            let createResponse = try await cognitoIDP.createUserPool(createRequest)
            self.userPoolId = createResponse.userPool!.id!
        }

        // does userpool client exist
        let listClientRequest = CognitoIdentityProvider.ListUserPoolClientsRequest(maxResults: 60, userPoolId: self.userPoolId)
        let clients = try await cognitoIDP.listUserPoolClients(listClientRequest).userPoolClients
        if let client = clients?.first(where: { $0.clientName == userPoolClientName }) {
            self.clientId = client.clientId!
            let describeRequest = CognitoIdentityProvider.DescribeUserPoolClientRequest(clientId: self.clientId, userPoolId: self.userPoolId)
            let describeResponse = try await cognitoIDP.describeUserPoolClient(describeRequest)
            self.clientSecret = describeResponse.userPoolClient!.clientSecret
        } else {
            // create userpool client
            let createClientRequest = CognitoIdentityProvider.CreateUserPoolClientRequest(
                clientName: self.userPoolClientName,
                explicitAuthFlows: [.allowAdminUserPasswordAuth, .allowUserPasswordAuth, .allowRefreshTokenAuth],
                generateSecret: true,
                userPoolId: self.userPoolId
            )
            let createClientResponse = try await cognitoIDP.createUserPoolClient(createClientRequest)
            self.clientId = createClientResponse.userPoolClient!.clientId!
            self.clientSecret = createClientResponse.userPoolClient!.clientSecret
        }
    }

    func setupIdentityPool() async throws {
        // create identity pool
        let providerName = "cognito-idp.\(self.region.rawValue).amazonaws.com/\(self.userPoolId!)"
        let createRequest = CognitoIdentity.CreateIdentityPoolInput(
            allowUnauthenticatedIdentities: false,
            cognitoIdentityProviders: [.init(clientId: self.clientId, providerName: providerName)],
            identityPoolName: self.identityPoolName
        )
        let createResponse = try await cognitoIdentity.createIdentityPool(createRequest)
        self.identityPoolId = createResponse.identityPoolId
    }

    func login(username: String, password: String, authenticatable: CognitoAuthenticatable) async throws -> CognitoAuthenticateResponse {
        let context = AWSCognitoContextTest()
        let response = try await authenticatable.authenticate(
            username: username,
            password: password,
            context: context
        )
        if case .challenged(let challenged) = response, let session = challenged.session {
            if challenged.name == .newPasswordRequired {
                return try await authenticatable.respondToNewPasswordChallenge(
                    username: username,
                    password: password,
                    session: session,
                    context: context
                )
            } else {
                throw AWSCognitoTestError.unrecognisedChallenge
            }
        }
        return response
    }

    /// create new user for test, run test and delete user
    func test(
        _ testName: String,
        attributes: [String: String] = [:],
        _ work: @escaping (String, String) async throws -> Void
    ) async throws {
        let username = testName + self.randomString()
        let messageHmac: HashedAuthenticationCode<SHA256> = HMAC.authenticationCode(
            for: Data(testName.utf8),
            using: SymmetricKey(data: Data(self.authenticatable.configuration.userPoolId.utf8))
        )
        let password = String(messageHmac.flatMap { String(format: "%x", $0) }) + "1!A"

        do {
            _ = try await self.authenticatable.createUser(
                username: username,
                attributes: attributes,
                temporaryPassword: password,
                messageAction: .suppress
            )
        } catch let error as CognitoIdentityProviderErrorType where error == .usernameExistsException {
            return
        }

        try await work(username, password)

        let deleteUserRequest = CognitoIdentityProvider.AdminDeleteUserRequest(username: username, userPoolId: self.authenticatable.configuration.userPoolId)
        try? await self.cognitoIDP.adminDeleteUser(deleteUserRequest)
    }

    func randomString() -> String {
        return String((0...7).map { _ in "abcdefghijklmnopqrstuvwxyz".randomElement()! })
    }

    // MARK: Tests

    func testAccessToken() async throws {
        XCTAssertNil(self.setUpFailure)
        try await self.test(#function) { username, password in
            let response = try await self.login(username: username, password: password, authenticatable: self.authenticatable)
            guard case .authenticated(let authenticated) = response else { throw AWSCognitoTestError.notAuthenticated }
            guard let accessToken = authenticated.accessToken else { throw AWSCognitoTestError.missingToken }

            let result = try await self.authenticatable.authenticate(accessToken: accessToken)
            XCTAssertEqual(result.username, username)
        }
    }

    func testIdToken() async throws {
        XCTAssertNil(self.setUpFailure)
        struct User: Codable {
            let email: String
            let givenName: String
            let familyName: String

            private enum CodingKeys: String, CodingKey {
                case email
                case givenName = "given_name"
                case familyName = "family_name"
            }
        }

        let attributes = ["given_name": "John", "family_name": "Smith", "email": "johnsmith@email.com"]
        try await self.test(#function, attributes: attributes) { username, password in
            let response = try await self.login(username: username, password: password, authenticatable: self.authenticatable)
            guard case .authenticated(let authenticated) = response else { throw AWSCognitoTestError.notAuthenticated }
            guard let idToken = authenticated.idToken else { throw AWSCognitoTestError.missingToken }
            let result: User = try await self.authenticatable.authenticate(idToken: idToken)

            XCTAssertEqual(result.email, attributes["email"])
            XCTAssertEqual(result.givenName, attributes["given_name"])
            XCTAssertEqual(result.familyName, attributes["family_name"])
        }
    }

    func testRefreshToken() async throws {
        XCTAssertNil(self.setUpFailure)
        try await self.test(#function) { username, password in
            let response = try await self.login(username: username, password: password, authenticatable: self.authenticatable)
            guard case .authenticated(let authenticated) = response else { throw AWSCognitoTestError.notAuthenticated }
            guard let refreshToken = authenticated.refreshToken else { throw AWSCognitoTestError.missingToken }

            let response2 = try await self.authenticatable.refresh(username: username, refreshToken: refreshToken)
            guard case .authenticated(let authenticated) = response2 else { throw AWSCognitoTestError.notAuthenticated }
            guard let accessToken = authenticated.accessToken else { throw AWSCognitoTestError.missingToken }

            _ = try await self.authenticatable.authenticate(accessToken: accessToken)
        }
    }

    func testAdminUpdateUserAttributes() async throws {
        XCTAssertNil(self.setUpFailure)
        struct User: Codable {
            let email: String
        }

        let attributes = ["email": "test@test.com"]
        let attributes2 = ["email": "test2@test2.com"]
        try await self.test(#function, attributes: attributes) { username, password in
            _ = try await self.authenticatable.updateUserAttributes(username: username, attributes: attributes2)
            let response = try await self.login(username: username, password: password, authenticatable: self.authenticatable)
            guard case .authenticated(let authenticated) = response else { throw AWSCognitoTestError.notAuthenticated }
            guard let idToken = authenticated.idToken else { throw AWSCognitoTestError.missingToken }

            let result: User = try await self.authenticatable.authenticate(idToken: idToken)
            XCTAssertEqual(result.email, attributes2["email"])
        }
    }

    func testNonAdminUpdateUserAttributes() async throws {
        XCTAssertNil(self.setUpFailure)
        struct User: Codable {
            let email: String
        }

        let attributes = ["email": "test@test.com"]
        let attributes2 = ["email": "test2@test2.com"]
        try await self.test(#function, attributes: attributes) { username, password in
            let response = try await self.login(username: username, password: password, authenticatable: self.authenticatable)
            guard case .authenticated(let authenticated) = response else { throw AWSCognitoTestError.notAuthenticated }
            guard let accessToken = authenticated.accessToken else { throw AWSCognitoTestError.missingToken }
            guard let idToken = authenticated.idToken else { throw AWSCognitoTestError.missingToken }

            let user: User = try await self.authenticatable.authenticate(idToken: idToken)

            XCTAssertEqual(user.email, attributes["email"])
            _ = try await self.authenticatable.updateUserAttributes(
                accessToken: accessToken,
                attributes: attributes2
            )
            let response2 = try await self.login(username: username, password: password, authenticatable: self.authenticatable)
            guard case .authenticated(let authenticated) = response2 else { throw AWSCognitoTestError.notAuthenticated }
            guard let idToken = authenticated.idToken else { throw AWSCognitoTestError.missingToken }
            let user2: User = try await self.authenticatable.authenticate(idToken: idToken)

            XCTAssertEqual(user2.email, attributes2["email"])
        }
    }

    func testUnauthenticatdClient() async throws {
        XCTAssertNil(self.setUpFailure)
        try await self.test(#function) { username, password in
            let awsClient = AWSClient(credentialProvider: .empty, httpClient: self.awsClient.httpClient)
            defer { XCTAssertNoThrow(try awsClient.syncShutdown()) }
            let cognitoIdentityProvider = CognitoIdentityProvider(client: awsClient, region: self.cognitoIDP.region)
            let configuration = CognitoConfiguration(
                userPoolId: self.authenticatable.configuration.userPoolId,
                clientId: self.authenticatable.configuration.clientId,
                clientSecret: self.authenticatable.configuration.clientSecret,
                cognitoIDP: cognitoIdentityProvider,
                adminClient: false
            )
            let authenticatable = CognitoAuthenticatable(configuration: configuration)

            let response = try await self.login(username: username, password: password, authenticatable: self.authenticatable)
            guard case .authenticated(let authenticated) = response else { throw AWSCognitoTestError.notAuthenticated }
            guard let accessToken = authenticated.accessToken else { throw AWSCognitoTestError.missingToken }

            let result = try await authenticatable.authenticate(accessToken: accessToken)
            XCTAssertEqual(result.username, username)
        }
    }

    func testRequireAuthenticatedClient() async throws {
        XCTAssertNil(self.setUpFailure)
        try await self.test(#function) { username, password in
            let awsClient = AWSClient(credentialProvider: .empty, httpClient: self.awsClient.httpClient)
            defer { XCTAssertNoThrow(try awsClient.syncShutdown()) }
            let cognitoIdentityProvider = CognitoIdentityProvider(client: awsClient, region: self.cognitoIDP.region)
            let configuration = CognitoConfiguration(
                userPoolId: self.authenticatable.configuration.userPoolId,
                clientId: self.authenticatable.configuration.clientId,
                clientSecret: self.authenticatable.configuration.clientSecret,
                cognitoIDP: cognitoIdentityProvider,
                adminClient: true
            )
            let authenticatable = CognitoAuthenticatable(configuration: configuration)

            do {
                _ = try await self.login(username: username, password: password, authenticatable: authenticatable)
                XCTFail("Login should fail")
            } catch SotoCognitoError.unauthorized {}
        }
    }

    func testAuthenticateFail() async throws {
        XCTAssertNil(self.setUpFailure)
        try await self.test(#function) { username, password in
            do {
                _ = try await self.authenticatable.authenticate(
                    username: username,
                    password: password + "!"
                )
                XCTFail("Login should fail")
            } catch SotoCognitoError.unauthorized {}
        }
    }

    func testIdentity() async throws {
        XCTAssertNil(self.setUpFailure)
        try await self.test(#function) { username, password in
            let response = try await self.login(username: username, password: password, authenticatable: self.authenticatable)
            guard case .authenticated(let authenticated) = response else { throw AWSCognitoTestError.notAuthenticated }
            guard let idToken = authenticated.idToken else { throw AWSCognitoTestError.missingToken }

            let id = try await self.identifiable.getIdentityId(idToken: idToken)
            do {
                _ = try await self.identifiable.getCredentialForIdentity(identityId: id, idToken: idToken)
                XCTFail("getCredentialForIdentity should fail")
            } catch let error as CognitoIdentityErrorType where error == .invalidIdentityPoolConfigurationException {
                // should get an invalid identity pool configuration error as the identity pool authentication provider
                // is setup as cognito userpools, but we havent set up a role to return
            }
        }
    }

    func testCredentialProvider() async throws {
        XCTAssertNil(self.setUpFailure)
        try await self.test(#function) { username, password in
            let credentialProvider: CredentialProviderFactory = .cognitoUserPool(
                userName: username,
                authentication: .password(password),
                userPoolId: self.userPoolId,
                clientId: self.clientId,
                clientSecret: self.clientSecret,
                identityPoolId: self.identityPoolId,
                region: self.region,
                respondToChallenge: { challenge, _, error in
                    switch challenge {
                    case .newPasswordRequired:
                        if error == nil {
                            return ["NEW_PASSWORD": "NewPassword123"]
                        } else {
                            return ["NEW_PASSWORD": "NewPassword123!"]
                        }
                    default:
                        return nil
                    }
                }
            )
            let client = AWSClient(credentialProvider: credentialProvider)
            do {
                _ = try await client.credentialProvider.getCredential(logger: AWSClient.loggingDisabled)
            } catch let error as CognitoIdentityErrorType where error == .invalidIdentityPoolConfigurationException {
            } catch {
                XCTFail()
            }
            try await client.shutdown()
        }
    }
}
