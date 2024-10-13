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

import BigNum
import Crypto
import Foundation
import NIO
import SotoCognitoAuthenticationKit
@testable import SotoCognitoAuthenticationSRP
import SotoCognitoIdentity
import SotoCognitoIdentityProvider
import SotoCore
@_spi(SotoInternal) import SotoSignerV4
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

func attempt(function: () throws -> Void) {
    do {
        try function()
    } catch {
        XCTFail("\(error)")
    }
}

enum AWSCognitoTestError: Error {
    case unrecognisedChallenge
    case notAuthenticated
    case missingToken
}

/// context object used for tests
public class AWSCognitoContextTest: CognitoContextData {
    public var contextData: CognitoIdentityProvider.ContextDataType? {
        return CognitoIdentityProvider.ContextDataType(httpHeaders: [], ipAddress: "127.0.0.1", serverName: "127.0.0.1", serverPath: "/")
    }
}

final class CognitoSRPTests: XCTestCase {
    var awsClient: AWSClient!
    var region: Region = .useast1
    var cognitoIDP: CognitoIdentityProvider!
    var cognitoIdentity: CognitoIdentity!
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
        self.awsClient = AWSClient(middleware: AWSLoggingMiddleware())
        self.cognitoIDP = CognitoIdentityProvider(client: self.awsClient, region: .useast1)
        self.cognitoIdentity = CognitoIdentity(client: self.awsClient, region: .useast1)
        do {
            try await self.setupUserPool()

            let configuration = CognitoConfiguration(
                userPoolId: userPoolId,
                clientId: clientId,
                clientSecret: self.clientSecret,
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
        } catch {
            self.setUpFailure = "\(error)"
        }
    }

    func setupUserPool() async throws {
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
                explicitAuthFlows: [.allowUserSrpAuth, .allowRefreshTokenAuth],
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

    override func tearDown() async throws {
        // delete client so we need to re-generate
        let deleteClientRequest = CognitoIdentityProvider.DeleteUserPoolClientRequest(clientId: self.clientId, userPoolId: self.userPoolId)
        try await self.cognitoIDP.deleteUserPoolClient(deleteClientRequest)
        try await self.awsClient.shutdown()
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

    func testAuthenticateSRP() async throws {
        XCTAssertNil(self.setUpFailure)

        let awsClient = AWSClient(credentialProvider: .empty, middleware: AWSLoggingMiddleware())
        defer { XCTAssertNoThrow(try awsClient.syncShutdown()) }
        let cognitoIDPUnauthenticated = CognitoIdentityProvider(client: awsClient, region: .useast1)
        let configuration = CognitoConfiguration(
            userPoolId: self.authenticatable.configuration.userPoolId,
            clientId: self.authenticatable.configuration.clientId,
            clientSecret: self.authenticatable.configuration.clientSecret,
            cognitoIDP: cognitoIDPUnauthenticated,
            adminClient: false
        )
        let authenticatable = CognitoAuthenticatable(configuration: configuration)

        try await test(#function) { username, password in
            let context = AWSCognitoContextTest()
            _ = try await authenticatable.authenticateSRP(username: username, password: password, context: context)
        }
    }

    /// create SRP for testing
    func createTestSRP() -> SRP<SHA256> {
        let a = BigNum(hex:
            "37981750af33fdf93fc6dce831fe794aba312572e7c33472528" +
                "54e5ce7c7f40343f5ad82f9ad3585c8cb1184c54c562f8317fc" +
                "2924c6c7ade72f1e8d964f606e040c8f9f0b12e3fe6b6828202" +
                "a5e40ca0103e880531921e56de3acc410331b8e5ddcd0dbf249" +
                "bfa104f6b797719613aa50eabcdb40fd5457f64861dd71890eba")
        return SRP<SHA256>(a: a)
    }

    func testSRPAValue() {
        let expectedA = BigNum(hex:
            "f93b917abccc667f4fac29d1e4c111bcd37d2c37577e7f113ad85030ec6" +
                "157c70dfee728ac4aee9a7631d85a68aec3ef72864b6e8a134f5c5eef89" +
                "40b93bb1db1ada9c1de770db282d644eeb3c551d35ce8de4d2cf98d0d79" +
                "9b6a7f1fe51568d11162ce0cded8246b630169dcfc2d5a43817d52f121b" +
                "3d75ab1a43dc30b7cec02e42e332d5fd781023d9c1fd44f3d1129d21155" +
                "0ce57c004aca95a367592705b517298f724e6314ffbac2425b2beb5095f" +
                "23b75dd3dd232adda700080d7a22a87383d3746d39f6427b7daf2a00683" +
                "038ff7dc099081b2bf43eb5e2e30465487dafb3cc875fdd9b475d46a0ac" +
                "1d07cf928fd11e06c5999596160168fc31228f7f3329d4b873acbf1540a" +
                "16418a3ee5a0a5070a3db558f5cf8cf15388ff0a6e4234bf1de3e5bade8" +
                "e4aa607d633a94a06bee4386c7444e06fd584282b9d576be318f0f20305" +
                "7e80996f79a2bb0a63ad4786d5cc12b1321bd6644e001cee194171f5b04" +
                "fcd65f3f280b6dadabae0401a9ae557ad27939730ce146319aa7f08d1e33")
        let srp = self.createTestSRP()
        XCTAssertEqual(expectedA, srp.A)
    }

    func testSRPKey() {
        let B = BigNum(hex:
            "a0812a0ee3fa8484a73addeb6a9afa145cff1eca2a6b86537a5d15132d" +
                "5811dd088d16e7d581b2798229350e6e473503cebddf19cabd3f14fb34" +
                "50a6858bafc972a29702d8772a22b000a160812a7fe29bcac2c36d43b9" +
                "1c118224626c2f0782d70f79c82ac5183e0d7d8c7b23ad0bda1f4fba94" +
                "1998bfc82e46415e49026bb33f8271cb9a56e69f518e90bc2f4c42c7bb" +
                "27720e25a14dcfbb5176effb3069a2bc627f18ec07a3e4118f61402dda" +
                "56a6da3f331d8c2cf78513d767b2bf040809e5a334c7bb98cb720ef565" +
                "4100cfa57d21155fc7630654964370fd512b30febc6c61bfa3415c7266" +
                "0c5dad3444881d272c3abd7ecec0e483493b1491391bef4348d1c27be7" +
                "00e443301fc856a9d1b6ca36fdc46eec9f3c51f0ea566f5a85c87d395d" +
                "3d9fc2a594945a860841d5b328f1910058b2bb822ac976d961736fac42" +
                "e84b46074762de8b254f37260e3b1da88529dd1060ca52b2dc9de5d773" +
                "72b1d74ea111de406aac964993133a6f172e8fae54eb885e6a3cd774f1" +
                "ca6be98b6ddc35")!
        let salt = BigNum(hex: "8dbcb21f18ae3216")!.bytes
        let expectedKey = BigNum(hex: "b70fad71e9658b24b0ec678774ecca30")!.bytes

        let srp = self.createTestSRP()
        let key = srp.getPasswordAuthenticationKey(username: "poolidtestuser", password: "testpassword", B: B, salt: salt)

        XCTAssertEqual(key, expectedKey)
    }

    func testHKDF() {
        let password = [UInt8]("password".utf8)
        let salt = [UInt8]("salt".utf8)
        let info = [UInt8]("HKDF key derivation".utf8)

        let sha1Result = SRP<Insecure.SHA1>.HKDF(seed: password, info: info, salt: salt, count: Insecure.SHA1.Digest.byteCount)
        XCTAssertEqual(sha1Result.hexDigest().uppercased(), "9912F20853DFF1AFA944E9B88CA63C410CBB1938")
        let sha256Result = SRP<SHA256>.HKDF(seed: password, info: info, salt: salt, count: 16)
        XCTAssertEqual(sha256Result.hexDigest().uppercased(), "398F838A6019FC27D99D90009A1FE0BF")
    }

    func testCredentialProvider() async throws {
        XCTAssertNil(self.setUpFailure)
        try await self.test(#function) { username, password in
            let credentialProvider: CredentialProviderFactory = .cognitoUserPool(
                userName: username,
                authentication: .srp(password),
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
                XCTFail("Error: \(error)")
            }
            try await client.shutdown()
        }
    }
}
