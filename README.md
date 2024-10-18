# Soto Cognito Authentication Kit
[<img src="http://img.shields.io/badge/swift-6.0-brightgreen.svg" alt="Swift 6.0" />](https://swift.org)
[<img src="https://github.com/soto-project/soto-cognito-authentication-kit/workflows/CI/badge.svg" />](https://github.com/soto-project/soto-cognito-authentication-kit/actions?query=workflow%3ACI)

Amazon Cognito provides authentication, authorization, and user management for your web apps. Soto Cognito Authentication Kit is a Swift interface to Cognito.

Table of Contents
-----------------

- [Using with Cognito User Pools](#using-with-cognito-user-pools)
    - [Configuration](#configuration)
    - [Creating a AWS Cognito user](#creating-a-aws-cognito-user)
    - [Authenticating with username and password](#authenticating-with-username-and-password)
    - [Verifying an access token is valid](#verifying-an-access-token-is-valid)
    - [Verifying the contents of an id token](#verifying-the-contents-of-an-id-token)
    - [Refreshing id and access tokens](#refreshing-id-and-access-tokens)
    - [Responding to authentication challenges](#responding-to-authentication-challenges)
    - [Creating user pools](#creating-user-pools)
- [Using with Cognito Identity Pools](#using-with-cognito-identity-pools)
    - [Configuration](#configuration-1)
    - [Accessing AWS credentials](#accessing-aws-credentials)
- [Secure Remote Password](#secure-remote-password)
- [Credential Provider](#credential-provider)
- [Reference](#reference)

## Using with Cognito User Pools

### Configuration
First you need to create an `CognitoConfiguration` instance that stores all your configuration information and create your `CognitoAuthenticatable` instance. 
```
let awsClient = AWSClient(httpClientProvider: .createNew)
let cognitoIdentityProvider = CognitoIdentityProvider(client: awsClient, region: .euwest1)
let configuration = CognitoConfiguration(
    userPoolId: "eu-west-1_userpoolid",
    clientId: "23432clientId234234",
    clientSecret: "1q9ln4m892j2secreta0dalh9a3aakmpeugiaag8k3cacijlbkrp",
    cognitoIDP: cognitoIdentityProvider,
    adminClient: true
)
let authenticatable = CognitoAuthenticatable(configuration: configuration)
```
The values `userPoolId`, `clientId` and `clientSecret` can all be found on the Amazon Cognito user pool [console](https://console.aws.amazon.com/cognito/users). `AWSClient` is the client used to communicate with Amazon Web Services and `CognitoIdentityProvider` provides the Cognito Identity Provider Userpool API. Both objects are provided by the [Soto](https://github.com/soto-project/soto.git) library. It is worthwhile reading up a little about these [here](https://soto.codes/user-guides/awsclient.html) and [here](https://soto.codes/user-guides/service-objects.html) before continuing. 

The `adminClient` parameter decides which set of `CognitoIdentityProvider` commands will be used. If set to `true` then the admin versions of the commands will be used. These require an `AWSClient` with AWS credentials. You can find more details about providing credentials [here](https://soto.codes/user-guides/credential-providers.html). Also a few commands like `createUser` are only available when `adminClient` is set to `true`. Whether you need to use an `adminClient` or not will be defined by the `authFlow` setup for your App client in the AWS console. If you are going to set `adminClient` to false then you can create your `AWSClient` as follows as you do not need AWS credentials.
```swift
let awsClient = AWSClient(
    credentialProvider: .empty, 
    httpClientProvider: .createNew
)
```
In general the admin versions of the commands are used by servers and the non-admin versions are used by client software.

### Creating a AWS Cognito user

Assuming we have the `CognitoAuthenticatable` instance from above the following can be used to create a user. As indicated above this function needs a configuration with `adminClient` set to `true`.
```
let username = "johndoe"
let attributes: [String: String] = ["email": "user@email.com", "name": "John Doe", "gender": "male"]
return authenticatable.createUser(username: username, attributes: attributes)
```
The attributes you provide should match the attributes you selected when creating the user pool in the AWS Cognito console. Once you've created a user an email is sent to them detailing their username and randomly generated password.

As an alternative you can use the `signUp` function which takes a `username` and `password`. This will send a confirmation email to the user which includes a confirmation code. You then call `confirmSignUp` with this confirmation code. For this path to be available you need to have the 'Allow users to sign themselves up' flag set in your user pool. 

### Authenticating with username and password

Once your user is created and confirmed in the signUp case. The following will generate JWT authentication tokens from a username and password. This function requires a `CognitoIdentityProvider` setup with AWS credentials, unless you pass the `requireAuthenticatedClient` parameter set to `false`.
```
let response = try await authenticatable.authenticate(
    username: username, 
    password: password,
    context: request
)
if case .authenticated(let authenticated) = response {
    let accessToken = authenticated.accessToken
    let idToken = authenticated.idToken
    let refreshToken = authenticated.refreshToken
...
```
The access token is used just to indicate a user has been granted access. It contains verification information, the username and a subject uuid which can be used to identify the user if you don't want to use the username. The token is valid for 60 minutes. The idToken contains claims about the identity of the user. It should contain all the attributes attached to the user. Again this token is only valid for 60 minutes. If you receive a `challenged` case then you have a login challenge and must respond to it before receiving authentication tokens. See [below](#responding-to-authentication-challenges). 

### Verifying an access token is valid

The following will verify whether a token gives access.
```
let response = try await authenticatable.authenticate(accessToken: token)
let username = response.username
let subject = response.subject
...
```
If the access token has expired, was not issued by the user pool or not created for the app client this call will return a failed `Future` with a unauthorized error.

### Verifying the contents of an id token

Id tokens contain the attributes of a user. As this varies between projects you have to provide a custom class to be filled out with these. The class needs to inherit from `Codable` and the `CodingKeys` need to reflect the keys provided by Amazon Web Services. These are defined in [OIDC Standard Claims](https://openid.net/specs/openid-connect-core-1_0.html#Claims). If you have custom attributes attached to your user these will be prefixed by "custom:". The following will extract the username, email, name and gender from an id token.
```
struct IdResponse: Codable {
    let email: String
    let username: String
    let name: String
    let gender: String
    
    private enum CodingKeys: String, CodingKey {
        case email = "email"
        case username = "cognito:username"
        case name = "name"
        case gender = "gender"
    }
}
let response = authenticatable.authenticate(idToken: token)
    .map { (response: IdResponse)->IdResponse in
        let email = response.email
        let username = response.username
        let name = response.name
        let gender = response.gender
        ...
        return response
}
```
NB The username tag in an ID Token is "cognito:username"

### Refreshing id and access tokens

To avoid having to ask the user for their username and password every 60 minutes a refresh token is also provided. You can use this to generate new id and access tokens whenever they have expired or are about to expire. The refresh token is valid for 30 days. Although you can edit the length of this in the Cognito console. 
```
let response = try await authenticatable.refresh(
    username: username, 
    refreshToken: refreshToken, 
    context: request
)
let accessToken = response.authenticated?.accessToken
let idToken = response.authenticated?.idToken
...
```

### Responding to authentication challenges

Sometimes when you try to authenticate a username and password or a refresh token you will be returned a challenge instead of the authentication tokens. An example of being when someone logs in for the first time they are required to change their password before they can continue. In this situation AWS Cognito returns a new password challenge. When you respond to this with a new password it provides you with the authentication tokens. Other situations would include Multi Factor Authentication. The following is responding to a change password request
```
let challengeName: CognitoChallengeName = .newPasswordRequired 
let challengeResponse: [String: String] = ["NEW_PASSWORD":"MyNewPassword1"]
let response = try await authenticatable.respondToChallenge(
    username: username, 
    name: challengeName, 
    responses: challengeResponse, 
    session: session, 
    context: request
)
let accessToken = response.authenticated?.accessToken
let idToken = response.authenticated?.idToken
let refreshToken = response.authenticated?.refreshToken
...
```
The `name` parameter is an enum containing all challenges. The `responses` parameter is a dictionary of inputs to the challenge. The `session` parameter was included in the challenge returned to you by the authentication request. If the challenge is successful you will get `response.authenticated` as a response. If another challenge is required then you will get details of that in `response.challenged`. There are custom versions of the `respondToChallenge` function for new password: `respondToNewPasswordChallenge` and for Multi Factor Authentication: `respondToMFAChallenge`.

### Creating user pools

There are a few settings that are required when creating your Cognito user pool, if you want to use it with the Soto Cognito Authentication library. Because the library uses the Admin level service calls device tracking is unavailable so ensure you set device remembering to off. Otherwise your refresh tokens will not work. 

When creating the app client for your user pool ensure you have 'Generate client secret' enabled. The Soto Cognito Authentication library automatically creates the secret hash required for user pools that have a client secret. It would be sensible to take advantage of this. As the library is designed to work on secured backend servers it uses the Admin no SRP authorization flow to authenticate users. You will also need to tick 'Enable username password auth for admin APIs for authentication (ALLOW_ADMIN_USER_PASSWORD_AUTH)' to ensure authentiation works. 

For more details on AWS Cognito User Pools you can find Amazon's documentation [here](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-identity-pools.html)

## Using with Cognito Identity Pools

Soto Cognito Authentication can be used to interface with Amazon Cognito Federated Identities, allowing you to create temporary credentials for accessing AWS services.

### Configuration

First you need to create an `CognitoIdentityConfiguration` instance that stores all your configuration information for interfacing with Amazon Cognito Federated Identities and a `CognitoIdentifiable` instance. 
```
let cognitoIdentity = CognitoIdentity(client: awsClient, region: .euwest1)
let configuration = CognitoIdentityConfiguration(
    identityPoolId: "eu-west-1_identitypoolid"
    identityProvider: "provider"
    cognitoIdentity: cognitoIdentity
)
let identifiable = CognitoIdentifiable(configuration: configuration)
```
The `identityPoolId` you can get from "Edit Identity Pool" section of the AWS console. `cognitoIdentity` is the client used to communicate with Amazon Web Services. It is provided by the [Soto](https://github.com/soto-project/soto.git) library. The `identityProvider` is whatever you setup in the AWS Cognito Identity Pool for providing authentication details.

### Accessing AWS credentials

There are two steps to accessing AWS credentials. First you need to get an identity id and then with that identity id you can get your AWS credentials. This can be done with the following.
```
let identity = identifiable.getIdentityId(idToken: idToken)
return identifiable.getCredentialForIdentity(identityId: identity, idToken: token)
```
In the situation you are using Cognito user pools the `idToken` is the `idToken` returned when you authenticate a user.

## Secure Remote Password

If you are using username/password authentication from a client it preferable you use Secure Remote Password to do your authentication. SRP is a secure password-based authentication and key-exchange protocol. It requires the client to show the server it knows of the user's password without actually passing the password to the server. Also the server does not store a copy of the password, instead it stores a verifier that can be used to verify the password is correct. A version of this is implemented in AWS Cognito and you can use it as follows
```swift
import SotoCognitoAuthenticationSRP

let response = authenticatable.authenticateSRP(
    username: username, 
    password: password,
    requireAuthenticatedClient: false
)
```

## Credential Provider

Soto Cognito Authentication Kit provides a credential provider that combines Cognito userpool authentication and Cognito Identity to generate credentials. It will refresh the credentials using the returned refresh token when required. It is setup as follows
```swift
let credentialProvider: CredentialProviderFactory = .cognitoUserPool(
    userName: username,
    authentication: .password(password),
    userPoolId: userPoolId,
    clientId: clientId,
    clientSecret: clientSecret,
    identityPoolId: identityPoolId,
    region: region,
    respondToChallenge: { challenge, parameters, error in
        // Respond to any challenges returned by userpool authentication
        // function parameters are
        // challenge: Challange type
        // parameters: Challenge parameters
        // error: Error returned from a previous respondToChallenge response
        switch challenge {
        case .newPasswordRequired:
            return try await respondToNewPassword()
        default:
            return nil
        }
    }
)
let client = AWSClient(credentialProvider: credentialProvider, httpClientProvider: .createNew)
```
The `authentication` parameter allows you to define how you want to authenticate with userpools. Possible option are `.password` which requires a password, `.refreshToken` which requires a refresh token you have already generated and if you have imported `SotoAuthenticationKitSRP` `.srp` gives you Secure Remote Password authentication.

### Reference

Reference documentation for SotoCognitoAuthenticationKit can be found [here](https://soto-project.github.io/soto-cognito-authentication-kit/index.html).
