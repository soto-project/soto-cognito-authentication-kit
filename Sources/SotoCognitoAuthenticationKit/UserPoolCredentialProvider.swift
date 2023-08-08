//===----------------------------------------------------------------------===//
//
// This source file is part of the Soto for AWS open source project
//
// Copyright (c) 2021 the Soto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of Soto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import SotoCognitoIdentity
import SotoCognitoIdentityProvider

/// Cognito authentication method used by `CredentialProviderFactory.cognitoUserPool`.
public struct CognitoAuthenticationMethod {
    public typealias Method = (CognitoAuthenticatable, String) async throws -> CognitoAuthenticateResponse
    let authenticate: Method

    public init(authenticate: @escaping Method) {
        self.authenticate = authenticate
    }
}

extension CognitoAuthenticationMethod {
    /// Authenticate with password
    public static func password(_ password: String) -> Self {
        return .init { authenticatable, userName in
            try await authenticatable.authenticate(
                username: userName,
                password: password,
                clientMetadata: nil,
                context: nil
            )
        }
    }

    /// Authenticate with refresh token
    public static func refreshToken(_ token: String) -> Self {
        return .init { authenticatable, userName in
            try await authenticatable.refresh(
                username: userName,
                refreshToken: token,
                clientMetadata: nil,
                context: nil
            )
        }
    }
}

actor UserPoolIdentityProvider: IdentityProvider {
    let userPoolIdentityProvider: String
    let authenticatable: CognitoAuthenticatable
    let respondToChallenge: (@Sendable (CognitoChallengeName, [String: String]?, Error?) async throws -> [String: String]?)?
    let maxChallengeResponseAttempts: Int
    let identityProviderContext: IdentityProviderFactory.Context
    var currentUserName: String
    var currentAuthentication: CognitoAuthenticationMethod
    var challengeResponseAttempts: Int

    init(
        userName: String,
        authentication: CognitoAuthenticationMethod,
        userPoolId: String,
        identityProviderContext: IdentityProviderFactory.Context,
        clientId: String,
        clientSecret: String? = nil,
        respondToChallenge: (@Sendable (CognitoChallengeName, [String: String]?, Error?) async throws -> [String: String]?)?,
        maxChallengeResponseAttempts: Int = 4
    ) {
        self.userPoolIdentityProvider = "cognito-idp.\(identityProviderContext.cognitoIdentity.region).amazonaws.com/\(userPoolId)"
        let cognitoIdentityProvider = CognitoIdentityProvider(
            client: identityProviderContext.cognitoIdentity.client,
            region: identityProviderContext.cognitoIdentity.region
        )
        let configuration = CognitoConfiguration(
            userPoolId: userPoolId,
            clientId: clientId,
            clientSecret: clientSecret,
            cognitoIDP: cognitoIdentityProvider,
            adminClient: false
        )
        self.identityProviderContext = identityProviderContext
        self.authenticatable = CognitoAuthenticatable(configuration: configuration)
        self.currentUserName = userName
        self.currentAuthentication = authentication
        self.respondToChallenge = respondToChallenge
        self.maxChallengeResponseAttempts = maxChallengeResponseAttempts
        self.challengeResponseAttempts = 0
    }

    func getIdentity(logger: Logging.Logger) async throws -> CognitoIdentity.IdentityParams {
        let idToken: String
        do {
            let authResponse = try await self.currentAuthentication.authenticate(self.authenticatable, self.currentUserName)
            idToken = try await self.respondToAuthenticateResponse(authResponse, challenge: nil)
        } catch {
            idToken = try await self.respondToAuthenticateError(error, challenge: nil)
        }
        let logins = [userPoolIdentityProvider: idToken]
        let request = CognitoIdentity.GetIdInput(identityPoolId: self.identityProviderContext.identityPoolId, logins: logins)
        let response = try await self.identityProviderContext.cognitoIdentity.getId(request, logger: self.identityProviderContext.logger)
        guard let identityId = response.identityId else { throw CredentialProviderError.noProvider }
        return .init(id: identityId, logins: logins)
    }

    func respondToAuthenticateResponse(_ response: CognitoAuthenticateResponse, challenge: CognitoAuthenticateResponse.ChallengedResponse?) async throws -> String {
        switch response {
        case .authenticated(let response):
            guard let idToken = response.idToken else {
                throw SotoCognitoError.unexpectedResult(reason: "Authenticated response does not authentication tokens")
            }
            // if we received a refresh token then this is not via a refresh authentication and we should attempt to get
            // the username from the access token to ensure we have the correct username
            if let refreshToken = response.refreshToken {
                self.currentAuthentication = .refreshToken(refreshToken)
                if let accessToken = response.accessToken {
                    let accessAuthenticateResponse = try await authenticatable.authenticate(accessToken: accessToken)
                    self.currentUserName = accessAuthenticateResponse.username
                }
            }
            return idToken
        case .challenged(let challenge):
            return try await self.respondToChallenge(challenge, error: nil)
        }
    }

    func respondToAuthenticateError(_ error: Error, challenge: CognitoAuthenticateResponse.ChallengedResponse?) async throws -> String {
        if let error = error as? CognitoIdentityProviderErrorType, let prevChallenge = challenge {
            return try await self.respondToChallenge(prevChallenge, error: error)
        } else {
            throw error
        }
    }

    func respondToChallenge(_ challenge: CognitoAuthenticateResponse.ChallengedResponse, error: Error?) async throws -> String {
        guard let challengeName = challenge.name else {
            throw SotoCognitoError.unexpectedResult(reason: "Challenge response does not have valid challenge name")
        }
        guard let respondToChallenge = respondToChallenge else {
            throw SotoCognitoError.unauthorized(reason: "Did not respond to challenge \(challengeName)")
        }
        guard self.challengeResponseAttempts < self.maxChallengeResponseAttempts else {
            throw SotoCognitoError.unauthorized(reason: "Failed to produce valid response to challenge \(challengeName)")
        }
        do {
            self.challengeResponseAttempts += 1
            let parameters = try await respondToChallenge(challengeName, challenge.parameters, error)
            guard let parameters = parameters else {
                throw SotoCognitoError.unauthorized(reason: "Did not respond to challenge \(challengeName)")
            }
            let challengeResponse = try await authenticatable.respondToChallenge(username: self.currentUserName, name: challengeName, responses: parameters, session: challenge.session)
            return try await self.respondToAuthenticateResponse(challengeResponse, challenge: challenge)
        } catch {
            return try await self.respondToAuthenticateError(error, challenge: challenge)
        }
    }
}

extension IdentityProviderFactory {
    /// Identity provider using Cognito userpools
    /*    static func cognitoUserPool(
             userName: String,
             authentication: CognitoAuthenticationMethod,
             userPoolId: String,
             clientId: String,
             clientSecret: String? = nil,
             respondToChallenge: ((CognitoChallengeName, [String: String]?, Error?) async throws -> [String: String]?)? = nil,
             maxChallengeResponseAttempts: Int = 4
         ) -> Self {
             var currentUserName = userName
             var currentAuthentication = authentication
             return externalIdentityProvider { context in
                 var challengeResponseAttempts = 0
                 let userPoolIdentityProvider = "cognito-idp.\(context.region).amazonaws.com/\(userPoolId)"
                 let cognitoIdentityProvider = CognitoIdentityProvider(client: context.client, region: context.region)
                 let configuration = CognitoConfiguration(
                     userPoolId: userPoolId,
                     clientId: clientId,
                     clientSecret: clientSecret,
                     cognitoIDP: cognitoIdentityProvider,
                     adminClient: false
                 )
                 let authenticatable = CognitoAuthenticatable(configuration: configuration)

                 func _respond(to response: CognitoAuthenticateResponse, challenge: CognitoAuthenticateResponse.ChallengedResponse?) async throws -> String {
                     switch response {
                     case .authenticated(let response):
                         guard let idToken = response.idToken else {
                             throw SotoCognitoError.unexpectedResult(reason: "Authenticated response does not authentication tokens")
                         }
                         // if we received a refresh token then this is not via a refresh authentication and we should attempt to get
                         // the username from the access token to ensure we have the correct username
                         if let refreshToken = response.refreshToken {
                             currentAuthentication = .refreshToken(refreshToken)
                             if let accessToken = response.accessToken {
                                 let accessAuthenticateResponse = try await authenticatable.authenticate(accessToken: accessToken)
                                 currentUserName = accessAuthenticateResponse.username
                             }
                         }
                         return idToken
                     case .challenged(let challenge):
                         return try await _respond(to: challenge, error: nil)
                     }
                 }

                 func _respondToAuthenticateError(to error: Error, challenge: CognitoAuthenticateResponse.ChallengedResponse?) async throws -> String {
                     if let error = error as? CognitoIdentityProviderErrorType, let prevChallenge = challenge {
                         return try await _respond(to: prevChallenge, error: error)
                     } else {
                         throw error
                     }
                 }

                 func _respond(to challenge: CognitoAuthenticateResponse.ChallengedResponse, error: Error?) async throws -> String {
                     guard let challengeName = challenge.name else {
                         throw SotoCognitoError.unexpectedResult(reason: "Challenge response does not have valid challenge name")
                     }
                     guard let respondToChallenge = respondToChallenge else {
                         throw SotoCognitoError.unauthorized(reason: "Did not respond to challenge \(challengeName)")
                     }
                     guard challengeResponseAttempts < maxChallengeResponseAttempts else {
                         throw SotoCognitoError.unauthorized(reason: "Failed to produce valid response to challenge \(challengeName)")
                     }
                     do {
                         challengeResponseAttempts += 1
                         let parameters = try await respondToChallenge(challengeName, challenge.parameters, error)
                         guard let parameters = parameters else {
                             throw SotoCognitoError.unauthorized(reason: "Did not respond to challenge \(challengeName)")
                         }
                         let challengeResponse = try await authenticatable.respondToChallenge(username: currentUserName, name: challengeName, responses: parameters, session: challenge.session)
                         return try await _respond(to: challengeResponse, challenge: challenge)
                     } catch {
                         return try await _respondToAuthenticateError(to: error, challenge: challenge)
                     }
                 }

                 do {
                     let authResponse = try await currentAuthentication.authenticate(authenticatable, currentUserName)
                     let idToken = try await _respond(to: authResponse, challenge: nil)
                     return [userPoolIdentityProvider: idToken]
                 } catch {
                     let idToken = try await _respondToAuthenticateError(to: error, challenge: nil)
                     return [userPoolIdentityProvider: idToken]
                 }

                 /*            func _respond(to challenge: CognitoAuthenticateResponse.ChallengedResponse, error: Error?) {
                      guard let challengeName = challenge.name
                      else {
                          tokenPromise.fail(SotoCognitoError.unexpectedResult(reason: "Challenge response does not have valid challenge name"))
                          return
                      }
                      guard let respondToChallenge = respondToChallenge else {
                          tokenPromise.fail(SotoCognitoError.unauthorized(reason: "Did not respond to challenge \(challengeName)"))
                          return
                      }
                      guard challengeResponseAttempts < maxChallengeResponseAttempts else {
                          tokenPromise.fail(SotoCognitoError.unauthorized(reason: "Failed to produce valid response to challenge \(challengeName)"))
                          return
                      }
                      respondToChallenge(challengeName, challenge.parameters, error, context.eventLoop)
                          .flatMap { parameters in
                              // if nil parameters is sent then throw did not respond error
                              guard let parameters = parameters else {
                                  return context.eventLoop.makeFailedFuture(SotoCognitoError.unauthorized(reason: "Did not respond to challenge \(challengeName)"))
                              }
                              return authenticatable.respondToChallenge(username: currentUserName, name: challengeName, responses: parameters, session: challenge.session)
                          }
                          .whenComplete { (result: Result<CognitoAuthenticateResponse, Error>) in
                              challengeResponseAttempts += 1
                              _respond(to: result, challenge: challenge)
                          }
                  }

                  func _respond(to result: Result<CognitoAuthenticateResponse, Error>, challenge: CognitoAuthenticateResponse.ChallengedResponse?) {
                      switch result {
                      case .success(.authenticated(let response)):
                          guard let idToken = response.idToken else {
                              tokenPromise.fail(SotoCognitoError.unexpectedResult(reason: "Authenticated response does not authentication tokens"))
                              return
                          }
                          // if we received a refresh token then this is not via a refresh authentication and we should attempt to get
                          // the username from the access token to ensure we have the correct username
                          if let refreshToken = response.refreshToken {
                              currentAuthentication = .refreshToken(refreshToken)
                              if let accessToken = response.accessToken {
                                  authenticatable.authenticate(accessToken: accessToken, on: context.eventLoop)
                                      .whenComplete { result in
                                          switch result {
                                          case .success(let response):
                                              currentUserName = response.username
                                              tokenPromise.succeed(idToken)
                                          case .failure(let error):
                                              tokenPromise.fail(error)
                                          }
                                      }
                              } else {
                                  tokenPromise.succeed(idToken)
                              }
                          } else {
                              tokenPromise.succeed(idToken)
                          }

                      case .success(.challenged(let challenge)):
                          _respond(to: challenge, error: nil)

                      case .failure(let error):
                          if let error = error as? CognitoIdentityProviderErrorType, let prevChallenge = challenge {
                              _respond(to: prevChallenge, error: error)
                          } else {
                              tokenPromise.fail(error)
                          }
                      }
                  }
                  currentAuthentication.authenticate(authenticatable, currentUserName, context.eventLoop).whenComplete { result in
                      _respond(to: result, challenge: nil)
                  }
                  return tokenPromise.futureResult.map { [userPoolIdentityProvider: $0] }*/
             }
         }
     }

     extension CredentialProviderFactory {
         /// Credential provider using Cognito userpool authentication
         ///
         /// You can authenticate with Cognito UserPools with various methods. Options available
         /// include `.password` and `.refreshToken`. If you import `SotoCognitoAuthenticationSRP`
         /// you also get secure remote password authentication with `.srp`.
         ///
         /// When authenticating, Cognito might respond with a challenge. Many of these challenges
         /// require user input. The `respondToChallenge` closure allows you to provide challenge
         /// response parameters. The respond to challenge closure is called with a challenge type
         /// the related input parameters, an error is the last challenge response produced an error and
         /// the `EventLoop` everything is running on. If you return `nil` that is considered a failed
         /// challenge and an error will be thrown. Below is a list of common challenges with the
         /// expected parameters to be returned.
         /// `.newPasswordRequired`: requires `NEW_PASSWORD`
         /// `.smsMfa`: `SMS_MFA_CODE`
         ///
         /// - Parameters:
         ///   - userName: user name to use for authentication
         ///   - authentication: Authentication method.
         ///   - userPoolId: Cognito UserPool ID
         ///   - clientId: Cognito UserPool client ID
         ///   - clientSecret: Cognito UserPool client secret
         ///   - identityPoolId: Cognito Identity pool if
         ///   - region: Region userpool and identity pool are in
         ///   - respondToChallenge: Respond to login challenge method
         ///   - logger: Logger
         public static func cognitoUserPool(
             userName: String,
             authentication: CognitoAuthenticationMethod,
             userPoolId: String,
             clientId: String,
             clientSecret: String? = nil,
             identityPoolId: String,
             region: Region,
             respondToChallenge: (@Sendable (CognitoChallengeName, [String: String]?, Error?) async throws -> [String: String]?)? = nil,
             maxChallengeResponseAttempts: Int = 4,
             logger: Logger = AWSClient.loggingDisabled
         ) -> CredentialProviderFactory {
             let identityProvider = IdentityProviderFactory.cognitoUserPool(
                 userName: userName,
                 authentication: authentication,
                 userPoolId: userPoolId,
                 clientId: clientId,
                 clientSecret: clientSecret,
                 respondToChallenge: respondToChallenge,
                 maxChallengeResponseAttempts: maxChallengeResponseAttempts
             )
             return .cognitoIdentity(
                 identityPoolId: identityPoolId,
                 identityProvider: identityProvider,
                 region: region,
                 logger: logger
             )
         }
     */ }
