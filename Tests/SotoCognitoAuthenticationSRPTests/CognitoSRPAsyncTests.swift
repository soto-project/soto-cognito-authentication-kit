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

#if compiler(>=5.5) && canImport(_Concurrency)

import BigNum
import Crypto
import Foundation
import NIO
import SotoCognitoAuthenticationKit
@testable import SotoCognitoAuthenticationSRP
import SotoCognitoIdentityProvider
import SotoCore
import XCTest

@available(macOS 12.0, iOS 15.0, watchOS 8.0, tvOS 15.0, *)
public func XCTRunAsyncAndBlock(_ closure: @escaping () async throws -> Void) {
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

@available(macOS 12.0, iOS 15.0, watchOS 8.0, tvOS 15.0, *)
final class CognitoSRPAsyncTests: XCTestCase {
    static var middlewares: [AWSServiceMiddleware] {
        ProcessInfo.processInfo.environment["CI"] == "true" ? [] : [AWSLoggingMiddleware()]
    }

    static let awsClient = AWSClient(middlewares: middlewares, httpClientProvider: .createNew)
    static let cognitoIDP = CognitoIdentityProvider(client: awsClient, region: .useast1)
    static let userPoolName: String = "aws-cognito-authentication-tests"
    static let userPoolClientName: String = UUID().uuidString
    static var authenticatable: CognitoAuthenticatable!
    static var userPoolId: String!
    static var clientId: String!

    static var setUpFailure: String?

    override class func setUp() {
        XCTRunAsyncAndBlock {
            do {
                let clientSecret: String?
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
                    clientSecret = describeResponse.userPoolClient!.clientSecret
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
                    clientSecret = createClientResponse.userPoolClient!.clientSecret
                }
                let configuration = CognitoConfiguration(
                    userPoolId: userPoolId,
                    clientId: clientId,
                    clientSecret: clientSecret,
                    cognitoIDP: self.cognitoIDP,
                    adminClient: true
                )
                Self.authenticatable = CognitoAuthenticatable(configuration: configuration)
            } catch {
                self.setUpFailure = "\(error)"
            }
        }
    }

    override class func tearDown() {
        XCTRunAsyncAndBlock {
            // delete client so we need to re-generate
            let deleteClientRequest = CognitoIdentityProvider.DeleteUserPoolClientRequest(clientId: Self.clientId, userPoolId: Self.userPoolId)
            try await self.cognitoIDP.deleteUserPoolClient(deleteClientRequest)
            try self.awsClient.syncShutdown()
        }
    }

    /// create new user for test, run test and delete user
    func test(
        _ testName: String,
        attributes: [String: String] = [:],
        _ work: @escaping (String, String) async throws -> Void
    ) {
        XCTRunAsyncAndBlock {
            let username = testName + Self.randomString()
            let messageHmac: HashedAuthenticationCode<SHA256> = HMAC.authenticationCode(
                for: Data(testName.utf8),
                using: SymmetricKey(data: Data(Self.authenticatable.configuration.userPoolId.utf8))
            )
            let password = messageHmac.description + "1!A"

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
    }

    static func randomString() -> String {
        return String((0...7).map { _ in "abcdefghijklmnopqrstuvwxyz".randomElement()! })
    }

    // MARK: Tests

    func testAuthenticateSRP() {
        XCTAssertNil(Self.setUpFailure)

        let awsClient = AWSClient(credentialProvider: .empty, middlewares: [AWSLoggingMiddleware()], httpClientProvider: .createNew)
        defer { XCTAssertNoThrow(try awsClient.syncShutdown()) }
        let cognitoIDPUnauthenticated = CognitoIdentityProvider(client: awsClient, region: .useast1)
        let configuration = CognitoConfiguration(
            userPoolId: Self.authenticatable.configuration.userPoolId,
            clientId: Self.authenticatable.configuration.clientId,
            clientSecret: Self.authenticatable.configuration.clientSecret,
            cognitoIDP: cognitoIDPUnauthenticated,
            adminClient: false
        )
        let authenticatable = CognitoAuthenticatable(configuration: configuration)

        test(#function) { username, password in
            let eventLoop = awsClient.eventLoopGroup.next()
            let context = AWSCognitoContextTest()

            _ = try await authenticatable.authenticateSRP(username: username, password: password, context: context, on: eventLoop)
        }
    }
}

#endif // compiler(>=5.5) && canImport(_Concurrency)
