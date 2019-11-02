# AWS Cognito Authentication

Amazon Cognito provides authentication, authorization, and user management for your web and mobile apps. This library provides access to this for Vapor server apps. 

# Using AWS Cognito Authentication
## Configuration
First you need to create an authentication object that stores all your configuration information
```
class Authentication : AWSCognitoAuthenticatable {
    static var userPoolId: String = "eu-west-1_userpoolid"
    static var clientId: String = "23432clientId234234"
    static var clientSecret: String = "1q9ln4m892j2cnsdapa0dalh9a3aakmpeugiaag8k3cacijlbkrp"
    static var cognitoIDP: CognitoIdentityProvider = CognitoIdentityProvider(region: .euwest1)
    static var region: Region = .euwest1
    static var jwtSigners: JWTSigners? = nil
}
```
The values `userPoolId`, `clientId` and `clientSecret` can all be find on the Amazon Cognito user pool console. `cognitoIDP` is the client used to communicate with Amazon Web Services. It is provided by the [aws-sdk-swift](https://github.com/swift-aws/aws-sdk-swift.git) library. `region` is the AWS server region your user pool is in. `jwtSigners` is used to store the Json Web Token signer objects created from the user pool Json Web Keys.

## Creating a AWS Cognito user
Assuming we have the `Authentication` class above the following can be used to create a user. 
```
let username = "johndoe"
let attributes: [String: String] = ["email": "user@email.com", "name": "John Doe", "gender": "male"]
return Authentication.createUser(username: username, attributes: attributes, on: req)
```
The attributes you provide should match the attributes you selected when creating the user pool in the AWS Cognito console. Once you've created a user an email is sent to them detailing their username and randomly generated password. The `on:` parameter is a Vapor Worker object. You can use the Request class here.

## Authenticating with a username and a password
The following will generate JWT authentication tokens from a username and password. 
```
let response = Authentication.authenticate(
    username: username, 
    password: password, 
    on: req)
    .then { response in
        let accessToken = response.authenticated?.accessToken
        let idToken = response.authenticated?.idToken
        let refreshToken = response.authenticated?.refreshToken
        ...
}
```
The access token is used just to indicate a user has been granted access. It contains verification information, the username and a subject uuid which can be used to identify the user if you don't want to use the username. The token is valid for 60 minutes. The idToken contains claims about the identity of the user. It should contain all the attributes attached to the user. Again this token is only valid for 60 minutes. 

## Refreshing id and access tokens
To avoid having to ask the user for their username and password every 60 minutes a refresh token is also provided. You can use this to generate new id and access tokens whenever they have expired or are about to expire. The refresh token is valid for 30 days. Although you can edit the length of this in the Cognito console. 
```
let response = Authentication.authenticate(
    username: username, 
    refreshToken: refreshToken, 
    on: req)
    .then { response in
        let accessToken = response.authenticated?.accessToken
        let idToken = response.authenticated?.idToken
        ...
}
```

## Verifying an access token is valid
The following will verify whether a token gives access.
```
let response = Authentication.authenticate(accessToken: token, on: req)
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
let response = Authentication.authenticate(idToken: token, on: req)
    .map { (response: IdResponse)->IdResponse in
        let email = response.email
        let username = response.username
        let name = response.name
        let gender = response.gender
        ...
        return response
}
```
NB The username tag in ID Token is "cognito:username"

## Responding to authentication challenges
Sometimes when you try to authenticate a username and password or a refresh token you will be returned a challenge instead of the authentication challenges. An example of being when someone logs in for the first time they are required to change their password before they can continue. In this situation AWS Cognito returns a new password challenge. When you respond to this with a new password it provides you with the authentication tokens. Other situations would include Multi Factor Authentication. The following is responding to the a change password request
```
let challengeName: AWSCognitoChallengeName = .newPasswordRequired 
let challengeResponse: [String: String] = ["NEW_PASSWORD":"MyNewPassword1"]
let response = Authentication.respondToChallenge(
    username: username, 
    name: challengeName, 
    responses: challengeResponse, 
    session: session, 
    on: req)
    .then { response in
        let accessToken = response.authenticated?.accessToken
        let idToken = response.authenticated?.idToken
        let refreshToken = response.authenticated?.refreshToken
        ...
}
```
The `name` parameter is an enum containing all challenges. The `responses` parameter is a dictionary of inputs to the challenge. The `session` parameter was included in the challenge returned to you by the authentication request. If the challenge is successful `response.authenticated` will not be `nil`. If another challenge is required then you will get details of that in `response.challenged`.

## Creating user pools
There are a few settings that are required when creating your user pool, if you want to use them with the AWS Cognito Authentication library. Because the library uses the Admin level service calls device tracking is unavailable. Ensure you set device remembering to off. Otherwise your refresh tokens will not work. When creating the app client for your user pool on the AWS Cognito console, ensure you have 'Generate client secret' enabled. The AWS Cognito Authentication library automatically creates the secret hash required for user pools that have a client secret. It would be sensible to take advantage of this. As the library is designed to work on backend secure servers it uses the Admin no SRP authorization flow to authenticate users so you will also need to tick 'Enable sign-in API for server-based authentication (ADMIN_NO_SRP_AUTH)'. 
