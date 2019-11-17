import BigInt
import Foundation
import NIO
import OpenCrypto

extension Data {

    init?(fromHexEncodedString string: String) {

        // Convert 0 ... 9, a ... f, A ...F to their decimal value,
        // return nil for all other input characters
        func decodeNibble(u: UInt16) -> UInt8? {
            switch(u) {
            case 0x30 ... 0x39:
                return UInt8(u - 0x30)
            case 0x41 ... 0x46:
                return UInt8(u - 0x41 + 10)
            case 0x61 ... 0x66:
                return UInt8(u - 0x61 + 10)
            default:
                return nil
            }
        }

        self.init(capacity: string.utf16.count/2)
        var even = true
        var byte: UInt8 = 0
        for c in string.utf16 {
            guard let val = decodeNibble(u: c) else { return nil }
            if even {
                byte = val << 4
            } else {
                byte += val
                self.append(byte)
            }
            even = !even
        }
        guard even else { return nil }
    }
}

extension AWSCognitoAuthenticatable {
    /// authenticate using SRP
    ///
    /// - parameters:
    ///     - username: user name for user
    ///     - password: password for user
    ///     - with: Eventloop and authenticate context. You can use a Vapor request here.
    /// - returns:
    ///     An authentication response. This can contain a challenge which the user has to fulfill before being allowed to login, or authentication access, id and refresh keys
    static func authenticateSRP(username: String, password: String, with eventLoopWithContext: AWSCognitoEventLoopWithContext) -> EventLoopFuture<AWSCognitoAuthenticateResponse> {
        let eventLoop = eventLoopWithContext.eventLoop
        return secretHashFuture(username: username, on: eventLoop).flatMap { secretHash in
            
            let N = BigUInt(
                "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C" +
                "9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE4" +
                "8E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B29" +
                "7BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9A" +
                "FD5138FE8376435B9FC61D2FC0EB06E3",
            radix: 16)!
            let g = BigUInt(2)
            let a = BigUInt(Data([UInt8].random(count: 128)))
            let A = g.power(a, modulus: N)
            
            
            
            let As = A.serialize().base64EncodedString()
            let authParameters : [String: String] = ["USERNAME":username,
                                                     "SECRET_HASH":secretHash,
                                                     "SRP_A": A.serialize().hexdigest()]
            return initiateAuthRequest(authFlow: .userSrpAuth, authParameters: authParameters, with: eventLoopWithContext)
                .flatMap { response in
                    guard let challenge = response.challenged,
                        let saltString = challenge.parameters?["SALT"],
                        let salt = Data(fromHexEncodedString: saltString),
                        let secretBlock = challenge.parameters?["SECRET_BLOCK"]?.data(using:.utf8) else { return eventLoop.makeFailedFuture(AWSCognitoError.unexpectedResult) }
                    
                    let B = BigUInt(secretBlock)
                    guard B % N != 0 else { return eventLoop.makeFailedFuture(AWSCognitoError.invalidPublicKey)}
                    
                    // calculate u
                    let size = N.serialize().count
                    let u = BigUInt(Hash(pad(A.serialize(), to:size) + pad(B.serialize(), to:size)))
                    // calculate k
                    let k = BigUInt(Hash(N.serialize() + pad(g.serialize(), to: size)))
                    // calculate x
                    let x = BigUInt(Hash(salt + Hash("\(username):\(password)".data(using: .utf8)!)))
                    // calculate v
                    let v = g.power(x, modulus: N)
                    
                    // shared secret
                    // S = (B - kg^x) ^ (a + ux)
                    // Note that v = g^x, and that B - kg^x might become negative, which
                    // cannot be stored in BigUInt. So we'll add N to B_ and make sure kv
                    // isn't greater than N.
                    let S = (B + N - k * v % N).power(a + u * x, modulus: N)

                    // session key
                    let K = Hash(S.serialize())

                    // client verification
                    let HN_xor_Hg = (Hash(N.serialize()) ^ Hash(g.serialize()))!
                    let HI = Hash(username.data(using: .utf8)!)
                    let M = Hash(HN_xor_Hg + HI + salt + A.serialize() + B.serialize() + K)
                    
                    // server verification
                    //let HAMK = Hash(A.serialize() + M + K)

                    return eventLoop.makeSucceededFuture(response)
            }
        }
    }

    static func pad(_ data: Data, to size: Int) -> Data {
        precondition(size >= data.count, "Negative padding not possible")
        return Data(count: size - data.count) + data
    }
    
    static func Hash(_ data: Data) -> Data {
        return Data(SHA256.hash(data: data))
    }
}

func ^ (lhs: Data, rhs: Data) -> Data? {
    guard lhs.count == rhs.count else { return nil }
    var result = Data(count: lhs.count)
    for index in lhs.indices {
        result[index] = lhs[index] ^ rhs[index]
    }
    return result
}

// Removed in Xcode 8 beta 3
func + (lhs: Data, rhs: Data) -> Data {
    var result = lhs
    result.append(rhs)
    return result
}
