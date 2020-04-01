import XCTest
import AWSSDKSwiftCore
import CognitoIdentityProvider
import BigNum
import Crypto
import NIO
import AWSCognitoAuthenticationKit
@testable import AWSCognitoAuthenticationSRP

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
public class AWSCognitoContextTest: AWSCognitoContextData {
    public var contextData: CognitoIdentityProvider.ContextDataType? {
        return CognitoIdentityProvider.ContextDataType(httpHeaders: [], ipAddress: "127.0.0.1", serverName: "127.0.0.1", serverPath: "/")
    }
}

final class AWSCognitoAuthenticationKitTests: XCTestCase {
    
    static let cognitoIDP = CognitoIdentityProvider(region: .useast1, /*middlewares: [AWSLoggingMiddleware()], */eventLoopGroupProvider: .shared(MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)))
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
    
    func testAuthenticateSRP() {
        XCTAssertNil(Self.setUpFailure)
        
        let cognitoIDPUnauthenticated = CognitoIdentityProvider(accessKeyId: "", secretAccessKey: "", region: .useast1, middlewares: [AWSLoggingMiddleware()], eventLoopGroupProvider: .shared(MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)))
        let configuration = AWSCognitoConfiguration(
            userPoolId: Self.authenticatable.configuration.userPoolId,
            clientId: Self.authenticatable.configuration.clientId,
            clientSecret: Self.authenticatable.configuration.clientSecret,
            cognitoIDP: cognitoIDPUnauthenticated,
            region: .useast1)
        let authenticatable = AWSCognitoAuthenticatable(configuration: configuration)
        
        attempt {
            let eventLoop = Self.cognitoIDP.client.eventLoopGroup.next()
            let context = AWSCognitoContextTest()
            let testData = try TestData(#function, on: eventLoop)
            
            let response = try authenticatable.authenticateSRP(username: testData.username, password: testData.password, context: context, on: eventLoop).wait()
            print(response)
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
        let srp = createTestSRP()
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
        let salt = BigNum(hex: "8dbcb21f18ae3216")!.data
        let expectedKey = BigNum(hex: "b70fad71e9658b24b0ec678774ecca30")!.data
        
        let srp = createTestSRP()
        let key = srp.getPasswordAuthenticationKey(username: "poolidtestuser", password: "testpassword", B: B, salt: salt)
        
        XCTAssertEqual(key, expectedKey)
    }
    
    func testHKDF() {
        let password = "password".data(using: .utf8)!
        let salt = "salt".data(using: .utf8)!
        let info = "HKDF key derivation".data(using: .utf8)!
        
        let sha1Result = SRP<Insecure.SHA1>.HKDF(seed: password, info: info, salt: salt, count: Insecure.SHA1.Digest.byteCount)
        XCTAssertEqual(sha1Result.hexdigest().uppercased(), "9912F20853DFF1AFA944E9B88CA63C410CBB1938")
        let sha256Result = SRP<SHA256>.HKDF(seed: password, info: info, salt: salt, count: 16)
        XCTAssertEqual(sha256Result.hexdigest().uppercased(), "398F838A6019FC27D99D90009A1FE0BF")
    }
    
    
    static var allTests = [
        ("testAuthenticateSRP", testAuthenticateSRP),
        ("testSRPAValue", testSRPAValue),
        ("testSRPKey", testSRPKey),
        ("testHKDF", testHKDF),
    ]
}

