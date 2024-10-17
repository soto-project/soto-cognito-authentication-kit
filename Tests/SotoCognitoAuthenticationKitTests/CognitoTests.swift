//===----------------------------------------------------------------------===//
//
// This source file is part of the Soto for AWS open source project
//
// Copyright (c) 2020-2024 the Soto project authors
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
@testable import SotoCognitoAuthenticationSRP
import SotoCognitoIdentity
import SotoCognitoIdentityProvider
import SotoCore
import Testing

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

struct EmptyMiddleware: AWSMiddlewareProtocol {
    func handle(_ request: AWSHTTPRequest, context: AWSMiddlewareContext, next: AWSMiddlewareNextHandler) async throws -> AWSHTTPResponse {
        return try await next(request, context)
    }
}

final class CognitoTests {
    let region: Region = .useast1

    func withAWSClient<Value>(
        credentialProvider: CredentialProviderFactory = .default,
        middleware: some AWSMiddlewareProtocol = EmptyMiddleware(),
        process: (AWSClient) async throws -> Value
    ) async throws -> Value {
        let awsClient = AWSClient(credentialProvider: credentialProvider, middleware: middleware)
        let value: Value
        do {
            value = try await process(awsClient)
        } catch {
            try? await awsClient.shutdown()
            throw error
        }
        try await awsClient.shutdown()
        return value
    }

    func withUserPool<Value>(
        awsClient: AWSClient,
        explicitAuthFlows: [CognitoIdentityProvider.ExplicitAuthFlowsType] = [.allowAdminUserPasswordAuth, .allowUserPasswordAuth, .allowRefreshTokenAuth],
        process: (CognitoAuthenticatable) async throws -> Value
    ) async throws -> Value {
        let cognitoIDP = CognitoIdentityProvider(client: awsClient, region: self.region)
        let ids = try await self.setupUserpool(cognitoIDP: cognitoIDP, explicitAuthFlows: explicitAuthFlows)

        let value: Value
        do {
            let configuration = CognitoConfiguration(
                userPoolId: ids.userPoolId,
                clientId: ids.clientId,
                clientSecret: ids.clientSecret,
                cognitoIDP: cognitoIDP,
                adminClient: true
            )
            let authenticatable = CognitoAuthenticatable(configuration: configuration)
            value = try await process(authenticatable)
        } catch {
            try await cognitoIDP.deleteUserPoolClient(clientId: ids.clientId, userPoolId: ids.userPoolId)
            try await cognitoIDP.deleteUserPool(userPoolId: ids.userPoolId)
            throw error
        }
        try await cognitoIDP.deleteUserPoolClient(clientId: ids.clientId, userPoolId: ids.userPoolId)
        try await cognitoIDP.deleteUserPool(userPoolId: ids.userPoolId)
        return value
    }

    func withIdentityPool<Value>(
        authenticatable: CognitoAuthenticatable,
        awsClient: AWSClient? = nil,
        process: (CognitoIdentifiable) async throws -> Value
    ) async throws -> Value {
        let awsClient = awsClient ?? authenticatable.configuration.cognitoIDP.client
        let cognitoIdentity = CognitoIdentity(client: awsClient, region: self.region)
        let identityPoolId = try await self.setupIdentityPool(
            cognitoIdentity: cognitoIdentity,
            userPoolId: authenticatable.configuration.userPoolId,
            clientId: authenticatable.configuration.clientId
        )

        let value: Value
        do {
            let identityConfiguration = CognitoIdentityConfiguration(
                identityPoolId: identityPoolId,
                userPoolId: authenticatable.configuration.userPoolId,
                region: self.region,
                cognitoIdentity: cognitoIdentity
            )
            let identifiable = CognitoIdentifiable(configuration: identityConfiguration)
            value = try await process(identifiable)
        } catch {
            try await cognitoIdentity.deleteIdentityPool(identityPoolId: identityPoolId)
            throw error
        }
        try await cognitoIdentity.deleteIdentityPool(identityPoolId: identityPoolId)
        return value
    }

    func setupUserpool(
        cognitoIDP: CognitoIdentityProvider,
        explicitAuthFlows: [CognitoIdentityProvider.ExplicitAuthFlowsType]
    ) async throws -> (userPoolId: String, clientId: String, clientSecret: String) {
        // does userpool exist
        let userPoolName = "aws-cognito-authentication-tests-\(UUID().uuidString)"
        // create userpool
        let createRequest = CognitoIdentityProvider.CreateUserPoolRequest(
            adminCreateUserConfig: CognitoIdentityProvider.AdminCreateUserConfigType(allowAdminCreateUserOnly: true),
            poolName: userPoolName
        )
        let createResponse = try await cognitoIDP.createUserPool(createRequest)
        let userPoolId = createResponse.userPool!.id!

        let userPoolClientName = UUID().uuidString
        // does userpool client exist
        // create userpool client
        let createClientRequest = CognitoIdentityProvider.CreateUserPoolClientRequest(
            clientName: userPoolClientName,
            explicitAuthFlows: explicitAuthFlows,
            generateSecret: true,
            userPoolId: userPoolId
        )
        let createClientResponse = try await cognitoIDP.createUserPoolClient(createClientRequest)
        let clientId = createClientResponse.userPoolClient!.clientId!
        let clientSecret = createClientResponse.userPoolClient!.clientSecret!
        return (userPoolId: userPoolId, clientId: clientId, clientSecret: clientSecret)
    }

    func setupIdentityPool(cognitoIdentity: CognitoIdentity, userPoolId: String, clientId: String) async throws -> String {
        // create identity pool
        let identityPoolName = UUID().uuidString
        let providerName = "cognito-idp.\(self.region.rawValue).amazonaws.com/\(userPoolId)"
        let createRequest = CognitoIdentity.CreateIdentityPoolInput(
            allowUnauthenticatedIdentities: false,
            cognitoIdentityProviders: [.init(clientId: clientId, providerName: providerName)],
            identityPoolName: identityPoolName
        )
        let createResponse = try await cognitoIdentity.createIdentityPool(createRequest)
        return createResponse.identityPoolId
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
        adminClient: Bool = true,
        attributes: [String: String] = [:],
        explicitAuthFlows: [CognitoIdentityProvider.ExplicitAuthFlowsType] = [.allowAdminUserPasswordAuth, .allowUserPasswordAuth, .allowRefreshTokenAuth],
        _ process: @escaping (CognitoAuthenticatable, String, String) async throws -> Void
    ) async throws {
        try await self.withAWSClient { client in
            try await self.withUserPool(awsClient: client, explicitAuthFlows: explicitAuthFlows) { authenticatable in
                let cognitoIDP = authenticatable.configuration.cognitoIDP
                let username = testName + self.randomString()
                let messageHmac: HashedAuthenticationCode<SHA256> = HMAC.authenticationCode(
                    for: Data(testName.utf8),
                    using: SymmetricKey(data: Data(authenticatable.configuration.userPoolId.utf8))
                )
                let password = String(messageHmac.flatMap { String(format: "%x", $0) }) + "1!A"

                do {
                    _ = try await authenticatable.createUser(
                        username: username,
                        attributes: attributes,
                        temporaryPassword: password,
                        messageAction: .suppress
                    )
                } catch let error as CognitoIdentityProviderErrorType where error == .usernameExistsException {
                    return
                }

                do {
                    if adminClient {
                        try await process(authenticatable, username, password)
                    } else {
                        try await self.withAWSClient(credentialProvider: .empty) { awsClient in
                            let cognitoIdentityProvider = CognitoIdentityProvider(client: awsClient, region: self.region)
                            let configuration = CognitoConfiguration(
                                userPoolId: authenticatable.configuration.userPoolId,
                                clientId: authenticatable.configuration.clientId,
                                clientSecret: authenticatable.configuration.clientSecret,
                                cognitoIDP: cognitoIdentityProvider,
                                adminClient: false
                            )
                            let authenticatable = CognitoAuthenticatable(configuration: configuration)
                            try await process(authenticatable, username, password)
                        }
                    }
                } catch {
                    try? await cognitoIDP.adminDeleteUser(username: username, userPoolId: authenticatable.configuration.userPoolId)
                    throw error
                }
                try? await cognitoIDP.adminDeleteUser(username: username, userPoolId: authenticatable.configuration.userPoolId)
            }
        }
    }

    func randomString() -> String {
        return String((0...7).map { _ in "abcdefghijklmnopqrstuvwxyz".randomElement()! })
    }

    // MARK: Tests

    @Test(arguments: [true, false])
    func testAccessToken(adminClient: Bool) async throws {
        try await self.test(#function, adminClient: adminClient) { authenticatable, username, password in
            let response = try await self.login(username: username, password: password, authenticatable: authenticatable)
            guard case .authenticated(let authenticated) = response else { throw AWSCognitoTestError.notAuthenticated }
            guard let accessToken = authenticated.accessToken else { throw AWSCognitoTestError.missingToken }

            let result = try await authenticatable.authenticate(accessToken: accessToken)
            #expect(result.username == username)
        }
    }

    @Test(arguments: [true, false])
    func testIdToken(adminClient: Bool) async throws {
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
        try await self.test(#function, adminClient: adminClient, attributes: attributes) { authenticatable, username, password in
            let response = try await self.login(username: username, password: password, authenticatable: authenticatable)
            guard case .authenticated(let authenticated) = response else { throw AWSCognitoTestError.notAuthenticated }
            guard let idToken = authenticated.idToken else { throw AWSCognitoTestError.missingToken }
            let result: User = try await authenticatable.authenticate(idToken: idToken)

            #expect(result.email == attributes["email"])
            #expect(result.givenName == attributes["given_name"])
            #expect(result.familyName == attributes["family_name"])
        }
    }

    @Test(arguments: [true, false])
    func testRefreshToken(adminClient: Bool) async throws {
        try await self.test(#function, adminClient: adminClient) { authenticatable, username, password in
            let response = try await self.login(username: username, password: password, authenticatable: authenticatable)
            guard case .authenticated(let authenticated) = response else { throw AWSCognitoTestError.notAuthenticated }
            guard let refreshToken = authenticated.refreshToken else { throw AWSCognitoTestError.missingToken }

            let response2 = try await authenticatable.refresh(username: username, refreshToken: refreshToken)
            guard case .authenticated(let authenticated) = response2 else { throw AWSCognitoTestError.notAuthenticated }
            guard let accessToken = authenticated.accessToken else { throw AWSCognitoTestError.missingToken }

            _ = try await authenticatable.authenticate(accessToken: accessToken)
        }
    }

    @Test
    func testAdminUpdateUserAttributes() async throws {
        struct User: Codable {
            let email: String
        }

        let attributes = ["email": "test@test.com"]
        let attributes2 = ["email": "test2@test2.com"]
        try await self.test(#function, attributes: attributes) { authenticatable, username, password in
            try await authenticatable.updateUserAttributes(username: username, attributes: attributes2)
            let response = try await self.login(username: username, password: password, authenticatable: authenticatable)
            guard case .authenticated(let authenticated) = response else { throw AWSCognitoTestError.notAuthenticated }
            guard let idToken = authenticated.idToken else { throw AWSCognitoTestError.missingToken }

            let result: User = try await authenticatable.authenticate(idToken: idToken)
            #expect(result.email == attributes2["email"])
        }
    }

    @Test
    func testNonAdminUpdateUserAttributes() async throws {
        struct User: Codable {
            let email: String
        }
        let attributes = ["email": "test@test.com"]
        let attributes2 = ["email": "test2@test2.com"]
        try await self.test(#function, adminClient: false, attributes: attributes) { authenticatable, username, password in
            let response = try await self.login(username: username, password: password, authenticatable: authenticatable)
            guard case .authenticated(let authenticated) = response else { throw AWSCognitoTestError.notAuthenticated }
            guard let accessToken = authenticated.accessToken else { throw AWSCognitoTestError.missingToken }
            guard let idToken = authenticated.idToken else { throw AWSCognitoTestError.missingToken }

            let user: User = try await authenticatable.authenticate(idToken: idToken)

            #expect(user.email == attributes["email"])
            _ = try await authenticatable.updateUserAttributes(
                accessToken: accessToken,
                attributes: attributes2
            )
            let response2 = try await self.login(username: username, password: password, authenticatable: authenticatable)
            guard case .authenticated(let authenticated) = response2 else { throw AWSCognitoTestError.notAuthenticated }
            guard let idToken = authenticated.idToken else { throw AWSCognitoTestError.missingToken }
            let user2: User = try await authenticatable.authenticate(idToken: idToken)

            #expect(user2.email == attributes2["email"])
        }
    }

    @Test
    func testAdminClientRequiresCredentials() async throws {
        try await self.test(#function) { authenticatable, username, password in
            try await self.withAWSClient(credentialProvider: .empty) { awsClient in
                let cognitoIdentityProvider = CognitoIdentityProvider(client: awsClient, region: self.region)
                let configuration = CognitoConfiguration(
                    userPoolId: authenticatable.configuration.userPoolId,
                    clientId: authenticatable.configuration.clientId,
                    clientSecret: authenticatable.configuration.clientSecret,
                    cognitoIDP: cognitoIdentityProvider,
                    adminClient: true
                )
                let authenticatable = CognitoAuthenticatable(configuration: configuration)

                do {
                    _ = try await self.login(username: username, password: password, authenticatable: authenticatable)
                    Issue.record("Login should fail")
                } catch SotoCognitoError.unauthorized {}
            }
        }
    }

    @Test
    func testAuthenticateFail() async throws {
        try await self.test(#function) { authenticatable, username, password in
            do {
                _ = try await authenticatable.authenticate(
                    username: username,
                    password: password + "!"
                )
                Issue.record("Login should fail")
            } catch SotoCognitoError.unauthorized {}
        }
    }

    @Test
    func testAuthenticateSRP() async throws {
        try await self.test(#function, explicitAuthFlows: [.allowUserSrpAuth, .allowRefreshTokenAuth]) { authenticatable, username, password in
            try await self.withAWSClient(credentialProvider: .empty) { awsClient in
                let cognitoIDPUnauthenticated = CognitoIdentityProvider(client: awsClient, region: .useast1)
                let configuration = CognitoConfiguration(
                    userPoolId: authenticatable.configuration.userPoolId,
                    clientId: authenticatable.configuration.clientId,
                    clientSecret: authenticatable.configuration.clientSecret,
                    cognitoIDP: cognitoIDPUnauthenticated,
                    adminClient: false
                )
                let authenticatable = CognitoAuthenticatable(configuration: configuration)
                let context = AWSCognitoContextTest()
                _ = try await authenticatable.authenticateSRP(username: username, password: password, context: context)
            }
        }
    }

    @Test
    func testIdentity() async throws {
        try await self.test(#function) { authenticatable, username, password in
            let response = try await self.login(username: username, password: password, authenticatable: authenticatable)
            guard case .authenticated(let authenticated) = response else { throw AWSCognitoTestError.notAuthenticated }
            guard let idToken = authenticated.idToken else { throw AWSCognitoTestError.missingToken }

            try await self.withIdentityPool(authenticatable: authenticatable) { identifiable in
                let id = try await identifiable.getIdentityId(idToken: idToken)
                do {
                    _ = try await identifiable.getCredentialForIdentity(identityId: id, idToken: idToken)
                    #expect(Bool(false), "getCredentialForIdentity should fail")
                } catch let error as CognitoIdentityErrorType where error == .invalidIdentityPoolConfigurationException {
                    // should get an invalid identity pool configuration error as the identity pool authentication provider
                    // is setup as cognito userpools, but we havent set up a role to return
                }
            }
        }
    }

    @Test(arguments: [
        [CognitoIdentityProvider.ExplicitAuthFlowsType.allowAdminUserPasswordAuth, .allowUserPasswordAuth, .allowRefreshTokenAuth],
        [.allowUserSrpAuth, .allowRefreshTokenAuth],
    ])
    func testCredentialProvider(explicitAuthFlows: [CognitoIdentityProvider.ExplicitAuthFlowsType]) async throws {
        try await self.test(#function, explicitAuthFlows: explicitAuthFlows) { authenticatable, username, password in
            try await self.withIdentityPool(authenticatable: authenticatable) { identifiable in
                let authenticationMethod = if explicitAuthFlows.first(where: { $0 == .allowUserSrpAuth }) != nil {
                    CognitoAuthenticationMethod.srp(password)
                } else {
                    CognitoAuthenticationMethod.password(password)
                }
                let credentialProvider: CredentialProviderFactory = .cognitoUserPool(
                    userName: username,
                    authentication: authenticationMethod,
                    userPoolId: authenticatable.configuration.userPoolId,
                    clientId: authenticatable.configuration.clientId,
                    clientSecret: authenticatable.configuration.clientSecret,
                    identityPoolId: identifiable.configuration.identityPoolId,
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
                try await self.withAWSClient(credentialProvider: credentialProvider) { client in
                    do {
                        _ = try await client.credentialProvider.getCredential(logger: AWSClient.loggingDisabled)
                    } catch let error as CognitoIdentityErrorType where error == .invalidIdentityPoolConfigurationException {}
                }
            }
        }
    }
}
