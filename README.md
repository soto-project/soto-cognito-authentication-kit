# AWS Cognito Authentication
[<img src="http://img.shields.io/badge/swift-5.1-brightgreen.svg" alt="Swift 5.1" />](https://swift.org)
[<img src="https://github.com/adam-fowler/aws-cognito-authentication/workflows/Swift/badge.svg" />](https://github.com/adam-fowler/aws-cognito-authentication/actions)

Amazon Cognito provides authentication, authorization, and user management for your web and mobile apps. This library provides access to this for Vapor server apps. 

# Using with Cognito User Pools

## Configuration
First you need to create an `AWSCognitoConfiguration` instance that stores all your configuration information and create your `AWSCognitoAuthenticatable` instance
```
let configuration = AWSCognitoConfiguration(
    userPoolId: String = "eu-west-1_userpoolid",
    clientId: String = "23432clientId234234",
    clientSecret: String = "1q9ln4m892j2cnsdapa0dalh9a3aakmpeugiaag8k3cacijlbkrp",
    cognitoIDP: CognitoIdentityProvider = CognitoIdentityProvider(region: .euwest1),
    region: Region = .euwest1
)
let authenticatable = AWSCognitoAuthenticatable(configuration: configuration)
```
The values `userPoolId`, `clientId` and `clientSecret` can all be find on the Amazon Cognito user pool console. `cognitoIDP` is the client used to communicate with Amazon Web Services. It is provided by the [aws-sdk-swift](https://github.com/swift-aws/aws-sdk-swift.git) library. `region` is the AWS server region your user pool is in.

## Creating a AWS Cognito user
Assuming we have the `AWSCognitoAuthenticatable` instance from above the following can be used to create a user. 
```
let username = "johndoe"
let attributes: [String: String] = ["email": "user@email.com", "name": "John Doe", "gender": "male"]
return authenticatable.createUser(username: username, attributes: attributes, on: request.eventLoop)
```
The attributes you provide should match the attributes you selected when creating the user pool in the AWS Cognito console. Once you've created a user an email is sent to them detailing their username and randomly generated password. The `on:` parameter is a Vapor Worker object. You can use the Request class here.

As an alternative you can use the `signUp` function which takes a `username` and `password`. This will send a confirmation email to the user which includes a confirmation code. You then call `confirmSignUp` with this confirmation code. For this path to be available you need to have the 'Allow users to sign themselves up' flag set in your user pool. 

## Authenticating with a username and a password
Once your user is created and confirmed in the signUp case. The following will generate JWT authentication tokens from a username and password. 
```
let response = authenticatable.authenticate(
    username: username, 
    password: password, 
    with: request)
    .then { response in
        let accessToken = response.authenticated?.accessToken
        let idToken = response.authenticated?.idToken
        let refreshToken = response.authenticated?.refreshToken
        ...
}
```
The access token is used just to indicate a user has been granted access. It contains verification information, the username and a subject uuid which can be used to identify the user if you don't want to use the username. The token is valid for 60 minutes. The idToken contains claims about the identity of the user. It should contain all the attributes attached to the user. Again this token is only valid for 60 minutes. 

## Verifying an access token is valid
The following will verify whether a token gives access.
```
let response = authenticatable.authenticate(accessToken: token, on: request.eventLoop)
    .then { response in
        let username = response.username
        let subject = response.subject
        ...
}
```
If the access token has expired, was not issued by the user pool or not created for the app client this call will return a failed `Future` with a unauthorized error.

## Verifying the contents of an id token
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
let response = authenticatable.authenticate(idToken: token, on: req.eventLoop)
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

## Refreshing id and access tokens
To avoid having to ask the user for their username and password every 60 minutes a refresh token is also provided. You can use this to generate new id and access tokens whenever they have expired or are about to expire. The refresh token is valid for 30 days. Although you can edit the length of this in the Cognito console. 
```
let response = authenticatable.authenticate(
    username: username, 
    refreshToken: refreshToken, 
    with: request)
    .then { response in
        let accessToken = response.authenticated?.accessToken
        let idToken = response.authenticated?.idToken
        ...
}
```

## Responding to authentication challenges
Sometimes when you try to authenticate a username and password or a refresh token you will be returned a challenge instead of the authentication challenges. An example of being when someone logs in for the first time they are required to change their password before they can continue. In this situation AWS Cognito returns a new password challenge. When you respond to this with a new password it provides you with the authentication tokens. Other situations would include Multi Factor Authentication. The following is responding to the a change password request
```
let challengeName: AWSCognitoChallengeName = .newPasswordRequired 
let challengeResponse: [String: String] = ["NEW_PASSWORD":"MyNewPassword1"]
let response = authenticatable.respondToChallenge(
    username: username, 
    name: challengeName, 
    responses: challengeResponse, 
    session: session, 
    with: request)
    .then { response in
        let accessToken = response.authenticated?.accessToken
        let idToken = response.authenticated?.idToken
        let refreshToken = response.authenticated?.refreshToken
        ...
}
```
The `name` parameter is an enum containing all challenges. The `responses` parameter is a dictionary of inputs to the challenge. The `session` parameter was included in the challenge returned to you by the authentication request. If the challenge is successful `response.authenticated` will not be `nil`. If another challenge is required then you will get details of that in `response.challenged`.

## Creating user pools
There are a few settings that are required when creating your Cognito user pool, if you want to use it with the AWS Cognito Authentication library. Because the library uses the Admin level service calls device tracking is unavailable so ensure you set device remembering to off. Otherwise your refresh tokens will not work. 

When creating the app client for your user pool ensure you have 'Generate client secret' enabled. The AWS Cognito Authentication library automatically creates the secret hash required for user pools that have a client secret. It would be sensible to take advantage of this. As the library is designed to work on secured backend servers it uses the Admin no SRP authorization flow to authenticate users. You will also need to tick 'Enable sign-in API for server-based authentication (ADMIN_NO_SRP_AUTH)' to ensure authentiation works. 

For more details on AWS Cognito User Pools you can find Amazon's documentation [here](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-identity-pools.html)

# Using with Cognito Identity Pools
AWS Cognito Authentication can be used to interface with Amazon Cognito Federated Identities, allowing you to create temporary credentials for accessing AWS services.

## Configuration
First you need to create an `AWSCognitoIdentityConfiguration` instance that stores all your configuration information for interfacing with Amazon Cognito Federated Identities and a `AWSCognitoIdentifiable` instance. 
```
let configuration = AWSCognitoIdentityConfiguration(
    identityPoolId: String = "eu-west-1_identitypoolid"
    identityProvider: String = "provider"
    cognitoIdentity: CognitoIdentity = CognitoIdentity(region: .euwest1)
)
let identifiable = AWSCognitoIdentifiable(configuration: configuration)
```
The `identityPoolId` you can get from "Edit Identity Pool" section of the AWS console. `cognitoIdentity` is the client used to communicate with Amazon Web Services. It is provided by the [aws-sdk-swift](https://github.com/swift-aws/aws-sdk-swift.git) library. The `identityProvider` is whatever you setup in the AWS Cognito Identity Pool for providing authentication details. If you are using this in conjunction with Cognito User Pools you can use the protocol `AWSCognitoUserPoolIdentifiable` which sets up the `identityProvider` for you. This conforms with the `AWSCognitoAuthenticatable` protocol so can be used for user pool actions as well.

## Accessing credentials
There are two steps to accessing AWS credentials. First you need to get an identity id and then with that identity id you can get your AWS credentials. This can be done with the following.
```
return identifiable.getIdentityId(idToken: idToken, on: req.eventLoop)
    .flatMap { identity in
        return identifiable.getCredentialForIdentity(identityId: identity, idToken: token, on: req.eventLoop)
}
```
In the situation you are using Cognito user pools the `idToken` is the `idToken` returned when you authenticate a user.
