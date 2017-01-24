//
//  NetAddress.swift
//  PerfectNet
//
//  Created by Kyle Jessup on 2017-01-23.
//
//

import PerfectThread

#if os(Linux)
	import SwiftGlibc
	let AF_UNSPEC: Int32 = 0
#else
	import Darwin
#endif

public enum NetSockType {
	case tcp, udp
	#if os(Linux)
	var rawValue: __socket_type {
		switch self {
		case .tcp: return SOCK_STREAM
		case .udp: return SOCK_DGRAM
		}
	}
	#else
	var rawValue: Int32 {
		switch self {
		case .tcp: return SOCK_STREAM
		case .udp: return SOCK_DGRAM
		}
	}
	#endif
}

public struct NetAddress {
	public let host: String
	public let port: UInt16
	public let addr: sockaddr_storage
	
	public init?(addr: sockaddr_storage) {
		var addr = addr
		var addrPtr = UnsafeMutablePointer(&addr)
		var len = socklen_t(MemoryLayout<sockaddr_storage>.size)
		let staticBufferSize = Int(INET6_ADDRSTRLEN)
		let buffer = UnsafeMutablePointer<Int8>.allocate(capacity: staticBufferSize)
		defer {
			buffer.deallocate(capacity: staticBufferSize)
		}
		let family = Int32(addr.ss_family)
		switch family {
		case AF_INET:
			self.port = addrPtr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
				inet_ntop(family, &$0.pointee.sin_addr, buffer, len)
				return $0.pointee.sin_port.netToHost
			}
		case AF_INET6:
			self.port = addrPtr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) {
				inet_ntop(family, &$0.pointee.sin6_addr, buffer, len)
				return $0.pointee.sin6_port.netToHost
			}
		default:
			return nil
		}
		guard let s = String(validatingUTF8: buffer) else {
			return nil
		}
		self.host = s
		self.addr = addr
	}
	
	public init?(host: String, port: UInt16, type: NetSockType = .tcp) {
		let aiFlags: Int32 = 0
		let family: Int32 = AF_UNSPEC
		let bPort = port.bigEndian
		var sin = sockaddr_storage()
		var hints = addrinfo(ai_flags: aiFlags, ai_family: family, ai_socktype: type.rawValue, ai_protocol: 0, ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
		var resultList = UnsafeMutablePointer<addrinfo>(bitPattern: 0)
		var result = getaddrinfo(host, nil, &hints, &resultList)
		while EAI_AGAIN == result {
			Threading.sleep(seconds: 0.1)
			result = getaddrinfo(host, nil, &hints, &resultList)
		}
		if result == EAI_NONAME {
			hints = addrinfo(ai_flags: aiFlags, ai_family: AF_INET6, ai_socktype: type.rawValue, ai_protocol: 0, ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
			result = getaddrinfo(host, nil, &hints, &resultList)
		}
		if result == 0, var resultList = resultList {
			defer {
				freeaddrinfo(resultList)
			}
			guard let addr = resultList.pointee.ai_addr else {
				return nil
			}
			switch Int32(addr.pointee.sa_family) {
			case AF_INET6:
				memcpy(&sin, addr, MemoryLayout<sockaddr_in6>.size)
				UnsafeMutablePointer(&sin).withMemoryRebound(to: sockaddr_in6.self, capacity: 1) {
					$0.pointee.sin6_port = in_port_t(bPort)
				}
			case AF_INET:
				memcpy(&sin, addr, MemoryLayout<sockaddr_in>.size)
				UnsafeMutablePointer(&sin).withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
					$0.pointee.sin_port = in_port_t(bPort)
				}
			default:
				return nil
			}
		} else {
			return nil
		}
		self.host = host
		self.port = port
		self.addr = sin
	}
}
