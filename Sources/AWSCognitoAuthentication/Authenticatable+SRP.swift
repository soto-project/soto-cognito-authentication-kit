import BigInt
import Foundation
import NIO
import OpenCrypto

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
            let srp = SRP<SHA256>()
            let authParameters : [String: String] = ["USERNAME":username,
                                                     "SECRET_HASH":secretHash,
                                                     "SRP_A": srp.A.serialize().hexdigest()]
            print("Parameters \(authParameters)")
            return initiateAuthRequest(authFlow: .userSrpAuth, authParameters: authParameters, with: eventLoopWithContext)
                .flatMap { response in
                    print("Response \(response)")
                    guard let challenge = response.challenged,
                        let parameters = challenge.parameters,
                        let salt = parameters["SALT"],
                        let secretBlockBase64 = parameters["SECRET_BLOCK"],
                        let secretBlock = Data(base64Encoded: secretBlockBase64),
                        let dataB = parameters["SRP_B"] else { return eventLoop.makeFailedFuture(AWSCognitoError.unexpectedResult) }
                    
                    let srpUsername = parameters["USER_ID_FOR_SRP"] ?? username
                    let userPoolName = userPoolId.split(separator: "_")[1]
                    
                    print("userpoolName: \(userPoolName)")
                    let B = BigUInt(dataB, radix: 16)!

                    // get key
                    guard let key = srp.getPasswordAuthenticationKey(username: "\(userPoolName)\(srpUsername)", password: password, B: B, salt: Data(salt.utf8)) else {
                        return eventLoop.makeFailedFuture(AWSCognitoError.invalidPublicKey)
                    }

                    let dateFormatter = DateFormatter()
                    dateFormatter.locale = Locale(identifier: "en_US_POSIX")
                    dateFormatter.dateFormat = "EEE MMM d HH:mm:ss z yyyy"
                    dateFormatter.timeZone = TimeZone(secondsFromGMT: 0)
                    let timestamp = dateFormatter.string(from: Date())
                    
                    // construct claim
                    let claim = SRP<SHA256>.HMAC(Data("\(userPoolName)\(srpUsername)".utf8) + secretBlock + Data(timestamp.utf8), key: key)
                                       
                    print("claim \(claim.hexdigest())")
                    let authResponse : [String: String] = ["USERNAME":username,
                                                             "SECRET_HASH":secretHash,
                                                             "PASSWORD_CLAIM_SECRET_BLOCK": secretBlockBase64,
                                                             "PASSWORD_CLAIM_SIGNATURE": claim.base64EncodedString(),
                                                             "TIMESTAMP": timestamp
                    ]
                    return respondToChallenge(username: username, name: .passwordVerifier, responses: authResponse, session: challenge.session, with: eventLoopWithContext)
            }
        }
    }
}

class SRP<H: HashFunction> {
    let N: BigUInt
    let g : BigUInt
    let k : BigInt
    let a : BigUInt
    let A : BigUInt
    let infoKey: Data

    init(N: BigUInt? = nil, g: BigUInt? = nil, a: BigUInt? = nil) {
        self.N = N ?? BigUInt(
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
        + "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
        radix: 16)!
        self.g = g ?? BigUInt(2)
        // k = H(N,g)
        self.k = BigUInt(Self.Hash(self.N.serialize() + self.g.serialize()))
        self.infoKey = Data("Caldera Derived Key".utf8)

        if let a = a {
            self.a = a
            self.A = self.g.power(a, modulus: self.N)
        } else {
            var a = BigUInt()
            var A = BigUInt()
            repeat {
                a = BigUInt(Self.HKDF(seed: Data([UInt8].random(count: 128)), info: infoKey, salt: Data(), count: 128))
                A = self.g.power(a, modulus: self.N)
            } while A % self.N == 0
            
            self.a = a
            print(a.serialize().hexdigest())
            self.A = A
        }
        
        print("g: \(self.g.serialize().hexdigest())")
        //print("k: \(k.serialize().hexdigest())")
        print("a: \(self.a.serialize().hexdigest())")
        print("N: \(self.N.serialize().hexdigest())")
        print("A: \(A.serialize().hexdigest())")
    }
    
    func getPasswordAuthenticationKey(username: String, password: String, B: BigUInt, salt: Data) -> Data? {
        print("Username: \(username)")
        print("Password: \(password)")
        print("B: \(B.serialize().hexdigest())")
        print("salt: \(salt)")
        
        guard B % N != 0 else { return nil }

        // calculate u = H(A,B)
        let u = BigUInt(Self.Hash(A.serialize() + B.serialize()))
        
       // print("u: \(u.serialize().hexdigest())")
        
        // calculate x = H(salt | H(poolName | userId | ":" | password))
        let message = Data("\(username):\(password)".utf8)
        let x = BigUInt(Self.Hash(salt + Self.Hash(message)))
        
       // print("x: \(x.serialize().hexdigest())")

        // calculate S
        let sS = ((BigInt(B) - BigInt(k) * BigInt(g).power(BigInt(x), modulus: BigInt(N))).power(BigInt(a) + BigInt(u) * BigInt(x), modulus: BigInt(N)) % BigInt(N))
        let S = sS.magnitude

        print("S: \(S.serialize().hexdigest())")

        let key = Self.HKDF(seed: S.serialize(), info: infoKey, salt: u.magnitude.serialize(), count: 16)

        print("key: \(key.hexdigest())")

        return key
    }    
    
    static func Hash<D>(_ data: D) -> Data where D: DataProtocol {
        return Data(H.hash(data: data))
    }
    
    static func HMAC(_ data: Data, key: Data) -> Data {
        let hmac: HashedAuthenticationCode<H> = OpenCrypto.HMAC.authenticationCode(for: data, using: SymmetricKey(data: key))
        return Data(hmac)
    }
    
    static func HKDF(seed: Data, info: Data, salt: Data, count: Int) -> Data {
        let prk = Self.HMAC(seed, key: salt)
        let iterations = Int(ceil(Double(count) / Double(H.Digest.byteCount)))
        
        var t = Data()
        var result = Data()
        for i in 1...iterations {
            var hmac: OpenCrypto.HMAC<H> = OpenCrypto.HMAC(key: SymmetricKey(data: prk))
            hmac.update(data: t)
            hmac.update(data: info)
            hmac.update(data: [UInt8(i)])
            t = Data(hmac.finalize())
            result += t
        }
        return Data(result[0..<count])
    }
}

// Removed in Xcode 8 beta 3
func + (lhs: Data, rhs: Data) -> Data {
    var result = lhs
    result.append(rhs)
    return result
}

