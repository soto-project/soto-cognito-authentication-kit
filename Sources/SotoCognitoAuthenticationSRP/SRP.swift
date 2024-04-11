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

/// Generates SRP password authentication key
struct SRP<H: HashFunction>: Sendable {
    let N: BigNum
    let g: BigNum
    let k: BigNum
    let a: BigNum
    let A: BigNum
    let infoKey: [UInt8]

    init(a: BigNum? = nil) {
        self.N = BigNum(hex:
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
                + "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF")!
        self.g = BigNum(2)
        // k = H(N,g)
        self.k = BigNum(bytes: [UInt8].init(H.hash(data: Self.pad(self.N.bytes) + self.g.bytes)))
        self.infoKey = [UInt8]("Caldera Derived Key".utf8)

        if let a {
            self.a = a
            self.A = self.g.power(a, modulus: self.N)
        } else {
            var a = BigNum()
            var A = BigNum()
            repeat {
                a = BigNum(bytes: Self.HKDF(seed: [UInt8].random(count: 128), info: self.infoKey, salt: [], count: 128))
                A = self.g.power(a, modulus: self.N)
            } while A % self.N == BigNum(0)

            self.a = a
            self.A = A
        }
    }

    /// return password authenticatino key given the username, password, B value and salt from the server
    func getPasswordAuthenticationKey(username: String, password: String, B: BigNum, salt: [UInt8]) -> [UInt8]? {
        guard B % self.N != BigNum(0) else { return nil }

        // calculate u = H(A,B)
        let u = BigNum(bytes: [UInt8].init(H.hash(data: Self.pad(self.A.bytes) + Self.pad(B.bytes))))

        // calculate x = H(salt | H(poolName | userId | ":" | password))
        let message = Data("\(username):\(password)".utf8)
        let x = BigNum(bytes: [UInt8].init(H.hash(data: Self.pad(salt) + H.hash(data: message))))

        // calculate S
        let S = (B - self.k * self.g.power(x, modulus: self.N)).power(self.a + u * x, modulus: self.N)

        let key = Self.HKDF(seed: Self.pad(S.bytes), info: self.infoKey, salt: Self.pad(u.bytes), count: 16)

        return key
    }

    /// pad buffer before hashing
    static func pad(_ data: [UInt8]) -> [UInt8] {
        if data[0] > 0x7F {
            return [0] + data
        }
        return data
    }

    static func HKDF(seed: [UInt8], info: [UInt8], salt: [UInt8], count: Int) -> [UInt8] {
        let prk = HMAC<H>.authenticationCode(for: seed, using: SymmetricKey(data: salt))
        let iterations = Int(ceil(Double(count) / Double(H.Digest.byteCount)))

        var t: [UInt8] = []
        var result: [UInt8] = []
        for i in 1...iterations {
            var hmac = HMAC<H>(key: SymmetricKey(data: prk))
            hmac.update(data: t)
            hmac.update(data: info)
            hmac.update(data: [UInt8(i)])
            t = [UInt8](hmac.finalize())
            result += t
        }
        return [UInt8](result[0..<count])
    }
}

extension Array where Element: FixedWidthInteger {
    static func random(count: Int) -> [Element] {
        var array = self.init()
        for _ in 0..<count {
            array.append(.random(in: Element.min..<Element.max))
        }
        return array
    }
}
