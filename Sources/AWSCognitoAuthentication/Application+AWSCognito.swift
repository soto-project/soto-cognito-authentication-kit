import Vapor


extension Application {
    public var awsCognito: AWSCognito {
        .init(application: self)
    }

    public struct AWSCognito {
        struct AuthenticatableKey: StorageKey {
            typealias Value = AWSCognitoAuthenticatable
        }

        public var authenticatable: AWSCognitoAuthenticatable {
            get {
                guard let authenticatable = self.application.storage[AuthenticatableKey.self] else {
                    fatalError("AWSCognito authenticatable not setup. Use application.awsCognito.authenticatable = ...")
                }
                return authenticatable
            }
            nonmutating set {
                self.application.storage[AuthenticatableKey.self] = newValue
            }
        }

        struct IdentifiableKey: StorageKey {
            typealias Value = AWSCognitoIdentifiable
        }

        public var identifiable: AWSCognitoIdentifiable? {
            get {
                guard let identifiable = self.application.storage[IdentifiableKey.self] else {
                    fatalError("AWSCognito identifiable not setup. Use application.awsCognito.identifiable = ...")
                }
                return identifiable
            }
            nonmutating set {
                self.application.storage[IdentifiableKey.self] = newValue
            }
        }

        let application: Application
    }
}
