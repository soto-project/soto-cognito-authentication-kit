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
    static var middleware: AWSMiddlewareProtocol? {
        ProcessInfo.processInfo.environment["CI"] == "true" ? nil : AWSLoggingMiddleware()
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

    static var setUpFailure: String?

    override class func setUp() {
        if ProcessInfo.processInfo.environment["CI"] == "true" {
            self.awsClient = AWSClient()
        } else {
            self.awsClient = AWSClient(middleware: AWSLoggingMiddleware())
        }

        self.cognitoIDP = CognitoIdentityProvider(client: self.awsClient, region: self.region)
        self.cognitoIdentity = CognitoIdentity(client: self.awsClient, region: self.region)
        XCTRunAsyncAndBlock {
            do {
                try await self.setupUserpool()

                let configuration = CognitoConfiguration(
                    userPoolId: userPoolId,
                    clientId: clientId,
                    clientSecret: clientSecret,
                    cognitoIDP: self.cognitoIDP,
                    adminClient: true
                )
                Self.authenticatable = CognitoAuthenticatable(configuration: configuration)

                try await self.setupIdentityPool()

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
                self.setUpFailure = error.localizedDescription
            }
        }
    }

    override class func tearDown() {
        XCTRunAsyncAndBlock {
            // delete client so we need to re-generate
            let deleteClientRequest = CognitoIdentityProvider.DeleteUserPoolClientRequest(clientId: Self.clientId, userPoolId: Self.userPoolId)
            try await self.cognitoIDP.deleteUserPoolClient(deleteClientRequest)
            let deleteIdentityPool = CognitoIdentity.DeleteIdentityPoolInput(identityPoolId: Self.identityPoolId)
            try await self.cognitoIdentity.deleteIdentityPool(deleteIdentityPool)
            try await self.awsClient.shutdown()
        }
    }

    static func setupUserpool() async throws {
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

    static func setupIdentityPool() async throws {
        // create identity pool
        let providerName = "cognito-idp.\(Self.region.rawValue).amazonaws.com/\(Self.userPoolId!)"
        let createRequest = CognitoIdentity.CreateIdentityPoolInput(
            allowUnauthenticatedIdentities: false,
            cognitoIdentityProviders: [.init(clientId: Self.clientId, providerName: providerName)],
            identityPoolName: self.identityPoolName
        )
        let createResponse = try await cognitoIdentity.createIdentityPool(createRequest)
        Self.identityPoolId = createResponse.identityPoolId
    }

    static func login(username: String, password: String, authenticatable: CognitoAuthenticatable) async throws -> CognitoAuthenticateResponse {
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
        _ work: @Sendable @escaping (String, String) async throws -> Void
    ) async throws {
        let username = testName + Self.randomString()
        let messageHmac: HashedAuthenticationCode<SHA256> = HMAC.authenticationCode(
            for: Data(testName.utf8),
            using: SymmetricKey(data: Data(Self.authenticatable.configuration.userPoolId.utf8))
        )
        let password = String(messageHmac.flatMap { String(format: "%x", $0) }) + "1!A"

        do {
            _ = try await Self.authenticatable.createUser(
                username: username,
                attributes: attributes,
                temporaryPassword: password,
                messageAction: .suppress
            )
        } catch let error as CognitoIdentityProviderErrorType where error == .usernameExistsException {
            return
        }

        try await work(username, password)

        let deleteUserRequest = CognitoIdentityProvider.AdminDeleteUserRequest(username: username, userPoolId: Self.authenticatable.configuration.userPoolId)
        try? await Self.cognitoIDP.adminDeleteUser(deleteUserRequest)
    }

    static func randomString() -> String {
        return String((0...7).map { _ in "abcdefghijklmnopqrstuvwxyz".randomElement()! })
    }

    // MARK: Tests

    func testAccessToken() async throws {
        XCTAssertNil(Self.setUpFailure)
        try await self.test(#function) { username, password in
            let response = try await Self.login(username: username, password: password, authenticatable: Self.authenticatable)
            guard case .authenticated(let authenticated) = response else { throw AWSCognitoTestError.notAuthenticated }
            guard let accessToken = authenticated.accessToken else { throw AWSCognitoTestError.missingToken }

            let result = try await Self.authenticatable.authenticate(accessToken: accessToken)
            XCTAssertEqual(result.username, username)
        }
    }

    func testIdToken() async throws {
        XCTAssertNil(Self.setUpFailure)
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
            let response = try await Self.login(username: username, password: password, authenticatable: Self.authenticatable)
            guard case .authenticated(let authenticated) = response else { throw AWSCognitoTestError.notAuthenticated }
            guard let idToken = authenticated.idToken else { throw AWSCognitoTestError.missingToken }
            let result: User = try await Self.authenticatable.authenticate(idToken: idToken)

            XCTAssertEqual(result.email, attributes["email"])
            XCTAssertEqual(result.givenName, attributes["given_name"])
            XCTAssertEqual(result.familyName, attributes["family_name"])
        }
    }

    func testRefreshToken() async throws {
        XCTAssertNil(Self.setUpFailure)
        try await self.test(#function) { username, password in
            let response = try await Self.login(username: username, password: password, authenticatable: Self.authenticatable)
            guard case .authenticated(let authenticated) = response else { throw AWSCognitoTestError.notAuthenticated }
            guard let refreshToken = authenticated.refreshToken else { throw AWSCognitoTestError.missingToken }

            let response2 = try await Self.authenticatable.refresh(username: username, refreshToken: refreshToken)
            guard case .authenticated(let authenticated) = response2 else { throw AWSCognitoTestError.notAuthenticated }
            guard let accessToken = authenticated.accessToken else { throw AWSCognitoTestError.missingToken }

            _ = try await Self.authenticatable.authenticate(accessToken: accessToken)
        }
    }

    func testAdminUpdateUserAttributes() async throws {
        XCTAssertNil(Self.setUpFailure)
        struct User: Codable {
            let email: String
        }

        let attributes = ["email": "test@test.com"]
        let attributes2 = ["email": "test2@test2.com"]
        try await self.test(#function, attributes: attributes) { username, password in
            _ = try await Self.authenticatable.updateUserAttributes(username: username, attributes: attributes2)
            let response = try await Self.login(username: username, password: password, authenticatable: Self.authenticatable)
            guard case .authenticated(let authenticated) = response else { throw AWSCognitoTestError.notAuthenticated }
            guard let idToken = authenticated.idToken else { throw AWSCognitoTestError.missingToken }

            let result: User = try await Self.authenticatable.authenticate(idToken: idToken)
            XCTAssertEqual(result.email, attributes2["email"])
        }
    }

    func testNonAdminUpdateUserAttributes() async throws {
        XCTAssertNil(Self.setUpFailure)
        struct User: Codable {
            let email: String
        }

        let attributes = ["email": "test@test.com"]
        let attributes2 = ["email": "test2@test2.com"]
        try await self.test(#function, attributes: attributes) { username, password in
            let response = try await Self.login(username: username, password: password, authenticatable: Self.authenticatable)
            guard case .authenticated(let authenticated) = response else { throw AWSCognitoTestError.notAuthenticated }
            guard let accessToken = authenticated.accessToken else { throw AWSCognitoTestError.missingToken }
            guard let idToken = authenticated.idToken else { throw AWSCognitoTestError.missingToken }

            let user: User = try await Self.authenticatable.authenticate(idToken: idToken)

            XCTAssertEqual(user.email, attributes["email"])
            _ = try await Self.authenticatable.updateUserAttributes(
                accessToken: accessToken,
                attributes: attributes2
            )
            let response2 = try await Self.login(username: username, password: password, authenticatable: Self.authenticatable)
            guard case .authenticated(let authenticated) = response2 else { throw AWSCognitoTestError.notAuthenticated }
            guard let idToken = authenticated.idToken else { throw AWSCognitoTestError.missingToken }
            let user2: User = try await Self.authenticatable.authenticate(idToken: idToken)

            XCTAssertEqual(user2.email, attributes2["email"])
        }
    }

    func testUnauthenticatdClient() async throws {
        XCTAssertNil(Self.setUpFailure)
        try await self.test(#function) { username, password in
            let awsClient = AWSClient(credentialProvider: .empty, httpClient: Self.awsClient.httpClient)
            defer { XCTAssertNoThrow(try awsClient.syncShutdown()) }
            let cognitoIdentityProvider = CognitoIdentityProvider(client: awsClient, region: Self.cognitoIDP.region)
            let configuration = CognitoConfiguration(
                userPoolId: Self.authenticatable.configuration.userPoolId,
                clientId: Self.authenticatable.configuration.clientId,
                clientSecret: Self.authenticatable.configuration.clientSecret,
                cognitoIDP: cognitoIdentityProvider,
                adminClient: false
            )
            let authenticatable = CognitoAuthenticatable(configuration: configuration)

            let response = try await Self.login(username: username, password: password, authenticatable: Self.authenticatable)
            guard case .authenticated(let authenticated) = response else { throw AWSCognitoTestError.notAuthenticated }
            guard let accessToken = authenticated.accessToken else { throw AWSCognitoTestError.missingToken }

            let result = try await authenticatable.authenticate(accessToken: accessToken)
            XCTAssertEqual(result.username, username)
        }
    }

    func testRequireAuthenticatedClient() async throws {
        XCTAssertNil(Self.setUpFailure)
        try await self.test(#function) { username, password in
            let awsClient = AWSClient(credentialProvider: .empty, httpClient: Self.awsClient.httpClient)
            defer { XCTAssertNoThrow(try awsClient.syncShutdown()) }
            let cognitoIdentityProvider = CognitoIdentityProvider(client: awsClient, region: Self.cognitoIDP.region)
            let configuration = CognitoConfiguration(
                userPoolId: Self.authenticatable.configuration.userPoolId,
                clientId: Self.authenticatable.configuration.clientId,
                clientSecret: Self.authenticatable.configuration.clientSecret,
                cognitoIDP: cognitoIdentityProvider,
                adminClient: true
            )
            let authenticatable = CognitoAuthenticatable(configuration: configuration)

            do {
                _ = try await Self.login(username: username, password: password, authenticatable: authenticatable)
                XCTFail("Login should fail")
            } catch SotoCognitoError.unauthorized {}
        }
    }

    func testAuthenticateFail() async throws {
        XCTAssertNil(Self.setUpFailure)
        try await self.test(#function) { username, password in
            do {
                _ = try await Self.authenticatable.authenticate(
                    username: username,
                    password: password + "!"
                )
                XCTFail("Login should fail")
            } catch SotoCognitoError.unauthorized {}
        }
    }

    func testIdentity() async throws {
        XCTAssertNil(Self.setUpFailure)
        try await self.test(#function) { username, password in
            let response = try await Self.login(username: username, password: password, authenticatable: Self.authenticatable)
            guard case .authenticated(let authenticated) = response else { throw AWSCognitoTestError.notAuthenticated }
            guard let idToken = authenticated.idToken else { throw AWSCognitoTestError.missingToken }

            let id = try await Self.identifiable.getIdentityId(idToken: idToken)
            do {
                _ = try await Self.identifiable.getCredentialForIdentity(identityId: id, idToken: idToken)
                XCTFail("getCredentialForIdentity should fail")
            } catch let error as CognitoIdentityErrorType where error == .invalidIdentityPoolConfigurationException {
                // should get an invalid identity pool configuration error as the identity pool authentication provider
                // is setup as cognito userpools, but we havent set up a role to return
            }
        }
    }

    func testCredentialProvider() async throws {
        XCTAssertNil(Self.setUpFailure)
        try await self.test(#function) { username, password in
            let credentialProvider: CredentialProviderFactory = .cognitoUserPool(
                userName: username,
                authentication: .password(password),
                userPoolId: Self.userPoolId,
                clientId: Self.clientId,
                clientSecret: Self.clientSecret,
                identityPoolId: Self.identityPoolId,
                region: Self.region,
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
