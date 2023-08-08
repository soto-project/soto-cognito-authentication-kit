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

import SotoCognitoAuthenticationKit

extension CognitoAuthenticationMethod {
    /// Authenticate with secure remote password
    public static func srp(_ password: String) -> Self {
        return .init { authenticatable, userName in
            try await authenticatable.authenticateSRP(
                username: userName,
                password: password,
                clientMetadata: nil,
                context: nil
            )
        }
    }
}
