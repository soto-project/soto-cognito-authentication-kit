//
//  File.swift
//  
//
//  Created by Adam Fowler on 11/12/2019.
//

import AWSCognitoAuthenticationKit
import Vapor

extension AWSCognitoAuthenticatable {
    /// helper function that returns if request with bearer token is cognito access authenticated
    /// - parameters:
    ///     - req: Vapor Request structure
    /// - returns:
    ///     An access token object that contains the user name and id
    static func authenticateAccessToken(_ req: Request) -> EventLoopFuture<AWSCognitoAccessToken> {
        guard let bearer = req.headers.bearerAuthorization else {
            return req.eventLoop.makeFailedFuture(AWSCognitoError.unauthorized(reason: "No bearer token"))
        }
        return authenticate(accessToken: bearer.token, on: req.eventLoop)
    }

    /// helper function that returns if request with bearer token is cognito id authenticated and returns contents in the payload type
    /// - parameters:
    ///     - req: Vapor Request structure
    /// - returns:
    ///     The payload contained in the token. See `authenticate<Payload: Codable>(idToken:on:)` for more details
    static func authenticateIdToken<Payload: Codable>(_ req: Request) -> EventLoopFuture<Payload> {
        guard let bearer = req.headers.bearerAuthorization else {
            return req.eventLoop.makeFailedFuture(AWSCognitoError.unauthorized(reason: "No bearer token"))
        }
        return authenticate(idToken: bearer.token, on: req.eventLoop)
    }
}
