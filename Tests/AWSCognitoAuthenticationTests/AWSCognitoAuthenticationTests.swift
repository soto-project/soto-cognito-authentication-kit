import XCTest
import AWSSDKSwiftCore
import CognitoIdentityProvider
import BigNum
import OpenCrypto
import NIO
import Vapor
@testable import AWSCognitoAuthentication

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
    static let cognitoIDP = CognitoIdentityProvider(region: .useast1, middlewares: [AWSLoggingMiddleware()], eventLoopGroupProvider: .shared(MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)))
    static var region: Region = .useast1
    static var jwtSigners: JWTSigners? = nil
    
    static var setUpFailure: String? = nil
    
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
            let messageHmac: HashedAuthenticationCode<SHA256> = HMAC.authenticationCode(for: Data(testName.utf8), using: SymmetricKey(data: Data(AWSCognitoAuthenticationTests.clientSecret.utf8)))
            self.password = messageHmac.description + "1!A"
            
            let create = AWSCognitoAuthenticationTests.createUser(username: self.username, attributes: attributes, temporaryPassword: password, messageAction:.suppress, on: eventloop)
                .map { _ in return }
                // deal with user already existing
                .flatMapErrorThrowing { error in
                    if let error = error as? Abort {
                        if error.status == .conflict && error.reason == "Username already exists" {
                            return
                        }
                    }
                    if case CognitoIdentityProviderErrorType.usernameExistsException(_) = error {
                        return
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
        XCTAssertNil(Self.setUpFailure)
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
        XCTAssertNil(Self.setUpFailure)
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
    
    func testAuthenticateSRP() {
        XCTAssertNil(Self.setUpFailure)
        attempt {
            let eventLoop = Self.cognitoIDP.client.eventLoopGroup.next()
            let context = AWSCognitoEventLoopWithContextTest(eventLoop)
            //let testData = try TestData(#function, on: eventLoop)
            
            let response = try AWSCognitoAuthenticationTests.authenticateSRP(username: "adamfowler", password: "Password1!", with: context).wait()
            print(response)
        }
    }
    
    /// create SRP for testing
    func createTestSRP() -> SRP<SHA256> {
        let N = BigNum(hex:
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        + "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        + "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        + "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        + "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        + "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
        + "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
        + "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
        + "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
        + "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
        + "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
        + "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
        + "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF")
        
        let g = BigNum(2)
        
        let a = BigNum(hex:
            "37981750af33fdf93fc6dce831fe794aba312572e7c33472528" +
            "54e5ce7c7f40343f5ad82f9ad3585c8cb1184c54c562f8317fc" +
            "2924c6c7ade72f1e8d964f606e040c8f9f0b12e3fe6b6828202" +
            "a5e40ca0103e880531921e56de3acc410331b8e5ddcd0dbf249" +
            "bfa104f6b797719613aa50eabcdb40fd5457f64861dd71890eba")
        return SRP<SHA256>(N: N, g: g, a: a)
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
            "ca6be98b6ddc35")
        let salt = BigNum(hex: "8dbcb21f18ae3216").data
        let expectedKey = BigNum(hex: "b70fad71e9658b24b0ec678774ecca30").data
        
        let srp = createTestSRP()
        let key = srp.getPasswordAuthenticationKey(username: "poolidtestuser", password: "testpassword", B: B, salt: salt)
        
        XCTAssertEqual(key, expectedKey)
    }
    
    func testClaimConstruction() {
        let username = "eiXF5hZ2vadamfowler"
        let secretblock = Data(base64Encoded: "Q5Vyu6s/DJYc4S+jdSbF1FuSiVmbaZzywVSZWmopvyRA4QzWiowM3K3uIqvlqHGLKCT2vGaA5e3nSuW1v7bL72Eg0FkRWDuESUudIa7qkiMWfNOI3s6E6yVUb2u9c2Tfv/y/+qNWRpoEHndpi9QaxWk55nI+2qI4E8/PbSOmvASTfBTrxhIEYefwLu76nWaA8L/Ri1yBYpDbFVCGZbeH7ZGHfHd7MtH6vRzfcobjM17gQSiw0FsV5qiBCBZ7e0NYG7Fp9rmkWqj+VzMs61OlZNS8Lr2Ng7FEbjFRmzBbrbXH/ARQdGH5ncVqh+m0nsN5351wamtzEDjJgSgah//IImKO4er1IZWgHMA2k+ZVacPTu6LV5Nol2GKP6bj3P6yKZ2tBOPSPkqmdZkTW+tx/wBm8m5aitMtiynm29CZLbkEDEpyA3brc6o/Sn5lohU6vmvaUOcMhO3Ctxsp0E+xFENvJq7UVQa5mTQLKr8prULiaWbmvgLdLGxmS+OKHrdpTz1FSpU2sUzVJDGrtL5SAMicZvt+PXO80Nf/i9iG2XCkCn4WbxqHlglor9MhKuDI+OIlBS44BUdJPSwmbU3O/4WI/Nce9GD9gPH5uEtCeEWsoTz0ZC4AFFu2xe/DODNcYlJyGrOm+lPef0MwPzimpJpaioR695DNDGuV8jJw/tkxwmqq6Moto6enuk3Z9tHC/8f8q62K1WSyDGZWR0pqyk+6ssWT2CpKcbqDTy+5Mw1Q4rLd/w7cBSv0gCQbSxKqaOMq1z/YFT9klm2Y061qMKfdrdxpEgHqQhr1OEERyTaZYUllLj4mRI2kHxdHf1RG95yijbYXRDgeVW7hwJuzVCAYlB0ENsbvtXsJ2TZ8zbz+CUMfnDjvqGmsyBE9oSksnaLi/X2/dpC6vm1ONA2P+D+sZ0pJe9YHTvZefATD6WBkx1BMvH3CoLcauaY+7oDqTlFqlgQ2T3I3rk2zMSoeyJE5H3qM1cuIHygbuySvM+gDUpv0XY0Nf7XNapLg2IxTo/8omTN1NpEWtuOERT8NOsD6Dg0FIK5nzMEsSGLC7Z3ifeH8rt3I8HDLEgXDuWZFSUYxnnxXQnDq9rYyJVh1m9mqvZkYkHWAbnqvTKroScifK7NlheyaH5XmCzvYSfDHF6VgahawtQFG5MrX/W9Cl5MOpYhdk3nUFs5lfvr60hmKZPubP6p5+vD6rD8b7X7BHczvS/UCs2rydjoAhGyS2OzMJ04Cza6pkjjyjApGuGjq/IPcsVNlB+M35FsUCicqW/x193JfM75CAwGITVmKPI0TGrPm48qbuVJFdTuEe99Ze5doJzDizpSHrsfcmye4YOC132HpT2DcNNgXZfbQd/TaciwhoRsJ1r4pjV4zsjCsMAGEsw3QfXjMomOIQsPDf4WkwlhwU3zfoJX9TxvycyMxtwEe1rjDQxsYyI8QnvyeplLNPeR5RJg2XA3kqsiO+qQ5F5y+3YZ3eEna++kz3t9dgQdrzXWmNdprS7ZL1mm0U01nda1ama46oKG9IV98yAfvO3ytp6hmuB3rG9eEVeP8npPDWpt04WThbSGLD6L9//Nzm7piWarNz/EQghul00tmmnGELGJgtjywMGD43K1M2av4QctEU0AA5x3giNK/lrtK9YEUcHje5ZH63e9nqh1MN2Vl1392jQ3U+HEc0ItwWhvH2EiAbbS7h2ytBB0i529h8HTaW4RlHMw==")!
        let timestamp = "Tue Nov 19 12:01:09 UTC 2019"
        let key = BigNum(hex: "717cd3fc38bcfd3dc5b8dd553bc9e7ba").data
        let claim = Self.constructClaim(username: username, secretBlock: secretblock, timestamp: timestamp, key: key)
        XCTAssertEqual(claim.base64EncodedString(), "6/T/wT0pcMySO6nsgsjWkgpAEs7pVyjYqrMRLirlRhI=")
    }
    
    func testSRPFixedValues() {
        let B = BigNum(hex: "e349cd79c3b3fc8b6c0dfdf8abc637132854f3e1cb4a2cf61e018eeef16969e02945b5332815e4a8be9cbabbfbd06a8295fbe3e88ae0224e40726c02818c102f36c6dec2124cc6b85633e281303970d6a42c91aec9984431571e9dfb3242e82478ceefd2b3a1d05bd693e8e87cfab9e63b456f6998c224e31e85fb089bf4011ff3db9f310e441f24ba8a0707910b68b7d391e4430a3791e23dcad19511a12b91d91c996a0221c68bf37089025c3beffd62383b3e47ae01573d206f2e07034b6a31ba91595a7fddeb77badd5f97fb0258cdeb3bc9188ee6d72cb8f378f3148b2d81a2b21c81b84ccff8d832a787485a4d942120697b1b75b583d29e3c72cc60dc60a0c493856fd20b0ef90d19b651887c352fe19c356d6121e3182c82e951f1976acbe785c54f7192ec77c8654d33683759ece3826084039060b528c372895bbb0ba0e3196ee69d1a2a9457010d37d120d144c33dfba9b80ea2c10c5061f513ef1bb584911161eea748f5bcdd1ae85edbdfd097431f80185370a0fe8c9b9d810f")
        let salt = BigNum(hex: "bc2674e7b495db8fd3e1e1cd1b880f2d").data
        let username = "q9qwidyuRadamfowler"
        let password = "Password1!"
        let secretblock = Data(base64Encoded: "cJEt5/A83MlCPmN1cqDAw9H7hKqq93BooB2bjAjCjKAYLwYRqI+gUsMqvtIcMZsrhpT67RVRB8CAREFj07CRdeKhGl4s4Gc3cvaKSqA+l/7S9cCmKmNrkviylCkI52ShqVmvyKdkI4r0XEfvACw1eJcn/N/ang8841FxLfqyMWCxzacOdOz1fWBG9lkk6P4FlVpCEXcZ18qnlD2yQkEMhyhzseQsgx37FRwCRyrvy75MoxDpbvp/tcohDg4FMK25SFcoKVAvt6JDDnL5FzOzV3St5EBsAT2BhK3K7Ptuf6kvskxCXU/Od0pmgy8weItK7jCKGydPrkyKsN6l9KJj0K8BIyMOMpPBLos73xSewbf5wCGR0YJe29jwvhkeilGhEfHtBBMLJO2S5dcGiuMshZDhhe7CzgYiim/tI6Gn0Hn3GCpGYcz6epSzlZ4ylhBhVGNvdM2mMvDTIlv7pHyawAzP6FkOinoC8NnvrrU9cc8h2lCqXwX6of+ezKFzrBKUdAW5qQ1lajhWM7A9eJQwSzUVk5bT3rxp2WmR4PWBlfE0I5k7w5l7smFVpJIViSdn+dHpHAqMc1dPQKMSp4k/SlSK1cCtTCsNoXb2A0RvbdyU2zNmq8WMVvv8KljsckZVw7MWmF7YbjpZNLwRgHi6L8kcdGcX8Vv98XWNL74RO8b32Iqz0fqDDASJwz4F9AwheYL9M46+IZ8KD3Nwd5aNtjJ4ZgfaGi+GyK7tDa9DWERE3TsNKw2yFHx/s4zoDsQhxPzoFb6m7WeXlf18OQNqS71NtCrGaQ0s3OLbUdF6apksf/+2sMDDqtKc2hp8//NzDxKp2SmD40aeygcHtT1owHfiPV/mbydJ2mDjCa/WQibj6PtXG210NOlNX2hpZtB/0h4Rb2f7YFt2bgRAnEaXXCC1uS9GDXo+Bm1WZCv0E6aGabUCJqE8yIepDGuO+vTMTmQPM7kAs3YCilpDPiAz/r2mQTRjYHJRV9cxrpNS5NPeNs9K+awSex9/VcWufWNQ24RFNFVwIgIAYKvpToayE1s7O8WxhMek7uNe8NaAlpkOZo3QZY5WplSQDSabH00BFKPqZrojcdPDz00mcbTfaB0fQIEcWIH8SOZVbL8fZabp/vrV1JIWx0ba09rl7DcOLPl5L5F/u+wcsZQ5wXDI5QCZvHDTqtO7lTdp3swgRDwmXTVXPwsZLs672AuNS5fevk7aPMwWjOdM1CittwvaMvqsYx9H7bm8jjrFeaNrafl9Sdx2I47eVUUOd5+y61E6CVhWQMm2XtYoPJgnLlT2qHtpQ1IMaeYW6/WyhdchpjY+sWPuhg68T86gaW96dqesp46vF4+fE7Gt6z5tfjYcTfWeVbCKzZMDyqQ7QPbC2iMegbRSX1k8GobtynokDC3qcTa5f5rdAYwO3IvkhrYpzfS/EK8rlwo+33ZSv+/gE51ud8ujRXD40/vVmubohCMSgxLh4T8zDNeRo9GhIFbKd1nULP/5x2jqqJubXSERqJw49eJ4kPdttI0D4V8TmGoSrM5KMiorMgqu6ljFobiMZCsL7esOytSIigsJUVFhS33/r0skftlwIEMrAvCJxa3kDv/3tXZwi2KLPz3L3VELELjGNpoOJA6jX7fom+oBXg2ZFEwvG6i2xgb+rb4luIhcw+IKm5UTzILavFjhqAEwtL+ikV0UAiO13aWp02JKoK4q2xbd+HqjIDztW/8=")!
        let timestamp = "Tue Nov 19 16:35:05 UTC 2019"

        let srp = createTestSRP()
        let key = srp.getPasswordAuthenticationKey(username: username, password: password, B: B, salt: salt)!
        print(key.hexdigest())
        let claim = Self.constructClaim(username: username, secretBlock: secretblock, timestamp: timestamp, key: key)
        print(claim.base64EncodedString())
    }
    
    /*func testRespond() {
        let authResponse : [String: String] = ["USERNAME":"adamfowler",
                                                 "SECRET_HASH":"r3Y8SKNDld6hDgdvuwr6gLA+k2Tvl4pl5nPEGiMyxGQ=",
                                                 "PASSWORD_CLAIM_SECRET_BLOCK": "3R+88IHVAaOJfOEP4q7cO0oLlM0sB1pRczGTfW0yMi0dYxiB6w4ME754lv+QHetb7pVHzEy6EiPb/iNz1Y/G0aLePLcMY3fk6sVkc+xbcDB4GVwgtiSOKo2bUwiK5Rpn/HEEHMdeymg/Fs6ijdWIEo8q2rrWvPZxKoJxgCphirlkPkcN5plFZDrO3zejMXVsbyUjxJ7MwoYQ1BBhXu2WFdjaRSoQwWnDZAsM/SiaqoErhCakF/uRFAKQQSoJjZ4DICG5Ykw6cg2ZvE3IUmnnzge+yblp2bIPAYJt6I4g8N+xrLP9cGTdyqIFEbgLQ+JKivuZvolFry+nDpDpcoVGxiPj1NfHlfdXuUl0lvCMABulFjLS5y83Rs8FpUVob3ESeRO3PNnt3B9ZDomu8piWvh0XDj7U9lmb0QrStICTmph0DQxR/w/LOuQC7FFA3us0EaceAm1tzwM3iSfY5OLgNQ/LGqEquajsLK0xLcbLBucz0ZXCTerasZTxDwp8WEtqMIU9dTfBtUyERdWwfH502B4NaoTuV+apYJfhkbe/tVkZ4GgQ4ivnslCeiTOG82dLc3txVU7FwwQNQOh53kFzvQxAooUDjh9mzC7SbheFbtLnTthrfYCzj9wRDd/3aleX7AdkQkvb9KS09ClL8kmyeuhIJHLR9ilXaV/lWvgk2SYO2lexcvpP4J6FXTFJyaQpJBLgS+eb+8PEltD0bLrkEwbq8pO+ETvj64yfxKp3M3BXFPDJCsFIuYeqkfx76p7vSE3l1ELRsCV79mH3iqIEHPhMM7ytmd6mK79AiAXhgzBXOiDK83eMj+m5o/xt/tBhFdNMZfFZ8HH5HyFOW7+yOhrEsXDB//g0ft4IXmQRFzr2DuZgp27nvfDC+vQropt+bXa/sNlEPsQ77tc+mP9Kc9nXcK2pOh4zvIF0m2eDZ8Lko2ph2/HBCen8I+20KW35qcNaygLA/ImOXGJ7lbT0Mv6OwWdu4xyEAa7QaSxj2ECSyVAbehXukP0BNaD8+a2lSU5C0uHPTss21z8F+TmVjIs4DUmhGtGiQIEzj122VKwgSoKHr7q8CDmwtGZTfZRj2ay9wPSq4/b0Wq4qqeWyozLsilznc+LlTRRqnP5Gc8k8DHrcK8Z4MBdVKR8fbeP2z/cICYiHXZEBv+Eaqrf34FtAqXLDSFTB+Amk+qoR4jS9uVLmX3FEVBEbsEOv9Sa8zgXTEa9PgHIXOAOuQ/UmTAp4IDlfyCcV9YLN7hInSlTcTtlaAe+srElWKre7wuIvG9ZzRGYhwCD0K3KzlbfDBUmiBM6y7LULGBmThTNj2uoMgmXefZvXpaxBLj8GoxvfNuG4ham91efF2rWOIwosZ9BKJTy8/BQ/DctlFSLjqtD9j27WIBmTqiny5xb5wAXOV4o35tEY8iSrcIro93phG5/vQatixoxoHLH+SyBRyywrV8MXelVq7I3zWbhnBDovnZzz716UV8StlFJRXBg4R3Cfyvnw9gtTPw8TZksh4iD9d83JNZfszbjGmhjDjvWR4MRp+rYFHDxpoOj9hp2r2g77dY23kan64uHr9zzcM+Gtq8Pb0MJGEqVizhHTSTjGF7Uur3nNzdHs18MQ+9zIzC2UGMbuYG+Lkoa/51iWC7kJv6OpHl8+/OoVbzpCvLl0DRf4EZjMiMRubiTkfxEe5SMeQp7omLF55kfPurBiKFEKcJeGgqwq9Qc4mQ==",
                                                 "PASSWORD_CLAIM_SIGNATURE": "qS0CHIIX/OSb1AzanFsufw9J0Q2dtGn3dzam/27DjFI=",
                                                 "TIMESTAMP": "Tue Nov 19 13:44:39 UTC 2019"
        ]
        attempt {
            //let eventLoop = Self.cognitoIDP.client.eventLoopGroup.next()
            //let context = AWSCognitoEventLoopWithContextTest(eventLoop)
            let request = CognitoIdentityProvider.AdminRespondToAuthChallengeRequest(challengeName: .passwordVerifier,
                                                                                     challengeResponses: authResponse,
                                                                                     clientId: Self.clientId,
                                                                                     userPoolId: Self.userPoolId)
            let result = try Self.cognitoIDP.adminRespondToAuthChallenge(request).wait()

            //let result = try Self.respondToChallenge(username: "adamfowler", name: .passwordVerifier, responses: authResponse, session: nil, with: context).wait()
            print(result)
        }

    }*/
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
        ("testAccessToken", testAccessToken),
        ("testIdToken", testIdToken),
        ("testRefreshToken", testRefreshToken),
    ]
}
