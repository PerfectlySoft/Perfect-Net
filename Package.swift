//
//  Package.swift
//  PerfectNet
//
//  Created by Kyle Jessup on 2016-05-02.
//	Copyright (C) 2016 PerfectlySoft, Inc.
//
//===----------------------------------------------------------------------===//
//
// This source file is part of the Perfect.org open source project
//
// Copyright (c) 2015 - 2016 PerfectlySoft Inc. and the Perfect project authors
// Licensed under Apache License v2.0
//
// See http://perfect.org/licensing.html for license information
//
//===----------------------------------------------------------------------===//
//

import PackageDescription

#if os(Linux)
let package = Package(
    name: "PerfectNet",
    targets: [],
    dependencies: [
        .Package(url: "https://github.com/PerfectlySoft/Perfect-OpenSSL-Linux.git", majorVersion: 0, minor: 3),
        .Package(url: "https://github.com/PerfectlySoft/Perfect-LinuxBridge.git", majorVersion: 0, minor: 4),
        .Package(url: "https://github.com/PerfectlySoft/Perfect-Thread.git", majorVersion: 0, minor: 2)
    ],
    exclude: []
)
#else
let package = Package(
    name: "PerfectNet",
    targets: [],
    dependencies: [
        .Package(url: "https://github.com/PerfectlySoft/Perfect-OpenSSL.git", majorVersion: 0, minor: 3),
        .Package(url: "https://github.com/PerfectlySoft/Perfect-Thread.git", majorVersion: 0, minor: 2)
    ],
    exclude: []
)
#endif
