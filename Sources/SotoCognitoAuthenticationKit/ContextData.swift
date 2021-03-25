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

import SotoCognitoIdentityProvider

/// Protocol for objects that contains context data to be used by Cognito
public protocol CognitoContextData {
    var contextData: CognitoIdentityProvider.ContextDataType? { get }
}
