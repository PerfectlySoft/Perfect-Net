//
//  NetTCP.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 7/5/15.
//	Copyright (C) 2015 PerfectlySoft, Inc.
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

import PerfectThread

#if os(Linux)
import SwiftGlibc
let AF_UNSPEC: Int32 = 0
let INADDR_NONE = UInt32(0xffffffff)
let EINPROGRESS = Int32(115)
#else
import Darwin
#endif

#if os(Linux)
	extension sockaddr_storage {
		var ss_len: Int8 {
			switch Int32(self.ss_family) {
			case AF_INET:
				return Int8(MemoryLayout<sockaddr_in>.size)
			case AF_INET6:
				return Int8(MemoryLayout<sockaddr_in6>.size)
			case AF_UNIX:
				return Int8(MemoryLayout<sockaddr_un>.size)
			default:
				return Int8(MemoryLayout<sockaddr>.size)
			}
		}
	}
	
	extension addrinfo {
		init(ai_flags: Int32, ai_family: Int32, ai_socktype: __socket_type, ai_protocol: Int32, ai_addrlen: socklen_t, ai_canonname: UnsafeMutablePointer<Int8>!, ai_addr: UnsafeMutablePointer<sockaddr>!, ai_next: UnsafeMutablePointer<addrinfo>!) {
			self.init(ai_flags: ai_flags, ai_family: ai_family, ai_socktype: Int32(ai_socktype.rawValue), ai_protocol: ai_protocol, ai_addrlen: ai_addrlen, ai_addr: ai_addr, ai_canonname: ai_canonname, ai_next: ai_next)
		}
	}
#endif

/// Provides an asynchronous IO wrapper around a file descriptor.
/// Fully realized for TCP socket types but can also serve as a base for sockets from other families, such as with `NetNamedPipe`/AF_UNIX.
public class NetTCP {
	
	final class ReferenceBuffer {
		var a: [UInt8]
		let size: Int
		init(size: Int) {
			self.size = size
			self.a = [UInt8](repeating: 0, count: size)
		}
		
		subscript(by: Int) -> UnsafeMutableRawPointer {
			return UnsafeMutableRawPointer(mutating: UnsafeRawPointer(self.a).advanced(by: by))
		}
	}
	
	private var networkFailure: Bool = false
	private let reasonableMaxReadCount = 1024 * 600 // <700k is emperically the largest chuck I was reading at a go
	
	public var fd: SocketFileDescriptor = SocketFileDescriptor(fd: invalidSocket, family: AF_UNSPEC)
	
    public var isValid: Bool { return self.fd.isValid }
    
	/// Create a new object with an initially invalid socket file descriptor.
	public init() {
		
	}
	
	/// Creates an instance which will use the given file descriptor
	/// - parameter fd: The pre-existing file descriptor
	public convenience init(fd: Int32) {
		self.init()
		self.fd.fd = fd
		self.fd.family = AF_INET
		self.fd.switchToNonBlocking()
	}
	
	@available(*, deprecated, message: "Call bind() or connect() to init socket")
	public func initSocket() {
		self.initSocket(family: AF_INET)
	}
	
	/// Allocates a new socket if it has not already been done.
	/// The functions `bind` and `connect` will call this method to ensure the socket has been allocated.
	/// Sub-classes should override this function in order to create their specialized socket.
	/// All sub-class sockets should be switched to utilize non-blocking IO by calling `SocketFileDescriptor.switchToNBIO()`.
	public func initSocket(family: Int32) {
		if fd.fd == invalidSocket {
		#if os(Linux)
			fd.fd = socket(family, Int32(SOCK_STREAM.rawValue), 0)
		#else
			fd.fd = socket(family, SOCK_STREAM, 0)
		#endif
			fd.family = family
			fd.switchToNonBlocking()
		}
	}
	
	public func sockName() -> (String, UInt16) {
		let staticBufferSize = Int(INET6_ADDRSTRLEN)
		var addr = sockaddr_storage()
		var addrPtr = UnsafeMutablePointer(&addr)
		var len = socklen_t(MemoryLayout<sockaddr_storage>.size)
		let buffer = UnsafeMutablePointer<Int8>.allocate(capacity: staticBufferSize)
		var port: in_port_t = 0
		defer {
			buffer.deallocate(capacity: staticBufferSize)
		}
		let result: Int32 = addrPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
			p in
			getsockname(fd.fd, p, &len)
		}
		guard result == 0 else {
			return ("", 0)
		}
		switch Int32(addr.ss_family) {
		case AF_INET:
			_ = addrPtr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
				inet_ntop(fd.family, &$0.pointee.sin_addr, buffer, len)
				port = $0.pointee.sin_port.netToHost
			}
		case AF_INET6:
			_ = addrPtr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) {
				inet_ntop(fd.family, &$0.pointee.sin6_addr, buffer, len)
				port = $0.pointee.sin6_port.netToHost
			}
		default:
			()
		}
		let s = String(validatingUTF8: buffer) ?? ""
		return (s, port)
	}
	
	public func peerName() -> (String, UInt16) {
		let staticBufferSize = Int(INET6_ADDRSTRLEN)
		var addr = sockaddr_storage()
		var addrPtr = UnsafeMutablePointer(&addr)
		var len = socklen_t(MemoryLayout<sockaddr_storage>.size)
		let buffer = UnsafeMutablePointer<Int8>.allocate(capacity: staticBufferSize)
		var port: in_port_t = 0
		defer {
			buffer.deallocate(capacity: staticBufferSize)
		}
		let result: Int32 = addrPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
			p in
			getpeername(fd.fd, p, &len)
		}
		guard result == 0 else {
			return ("", 0)
		}
		switch Int32(addr.ss_family) {
		case AF_INET:
			_ = addrPtr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
				inet_ntop(fd.family, &$0.pointee.sin_addr, buffer, len)
				port = $0.pointee.sin_port.netToHost
			}
		case AF_INET6:
			_ = addrPtr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) {
				inet_ntop(fd.family, &$0.pointee.sin6_addr, buffer, len)
				port = $0.pointee.sin6_port.netToHost
			}
		default:
			()
		}
		let s = String(validatingUTF8: buffer) ?? ""
		return (s, port)
	}
	
	func isEAgain(err er: Int) -> Bool {
		return er == -1 && errno == EAGAIN
	}
	
	/// Bind the socket on the given port and optional local address
	/// - parameter port: The port on which to bind
	/// - parameter address: The the local address, given as a string, on which to bind. Defaults to "0.0.0.0".
	/// - throws: PerfectError.NetworkError
	public func bind(port prt: UInt16, address: String = "0.0.0.0") throws {
		var addr = sockaddr_storage()
		let res = makeAddress(&addr, host: address, port: prt, binding: true)
		guard res != -1 else {
			try ThrowNetworkError()
		}
		initSocket(family: Int32(addr.ss_family))
		let bRes: Int32 = UnsafeMutablePointer(&addr).withMemoryRebound(to: sockaddr.self, capacity: 1) {
			saddr in
			#if os(Linux)
				return SwiftGlibc.bind(self.fd.fd, saddr, socklen_t(addr.ss_len))
			#else
				return Darwin.bind(self.fd.fd, saddr, socklen_t(addr.ss_len))
			#endif
		}
		if bRes == -1 {
			try ThrowNetworkError()
		}
	}
	
	/// Switches the socket to server mode. Socket should have been previously bound using the `bind` function.
	public func listen(backlog: Int32 = 128) {
	#if os(Linux)
		_ = SwiftGlibc.listen(fd.fd, backlog)
	#else
		_ = Darwin.listen(fd.fd, backlog)
	#endif
	}
	
	/// Shuts down and closes the socket.
	/// The object may be reused.
	public func close() {
		if fd.fd != invalidSocket {
		#if os(Linux)
			shutdown(fd.fd, 2) // !FIX!
			_ = SwiftGlibc.close(fd.fd)
		#else
			shutdown(fd.fd, SHUT_RDWR)
			_ = Darwin.close(fd.fd)
		#endif
			fd.fd = invalidSocket
        }
	}
	
	func recv(into buf: UnsafeMutableRawPointer, count: Int) -> Int {
	#if os(Linux)
		return SwiftGlibc.recv(self.fd.fd, buf, count, 0)
	#else
		return Darwin.recv(self.fd.fd, buf, count, 0)
	#endif
	}
	
	func send(_ buf: [UInt8], offsetBy: Int, count: Int) -> Int {
		let ptr = UnsafeRawPointer(buf).advanced(by: offsetBy)
	#if os(Linux)
		return SwiftGlibc.send(self.fd.fd, ptr, count, 0)
	#else
		return Darwin.send(self.fd.fd, ptr, count, 0)
	#endif
	}
	
	func makeAddress(_ sin: inout sockaddr_storage, host: String, port: UInt16, binding: Bool = false) -> Int {
		let aiFlags: Int32 = 0
		let family: Int32 = AF_UNSPEC
		let bPort = port.bigEndian
		var hints = addrinfo(ai_flags: aiFlags, ai_family: family, ai_socktype: SOCK_STREAM, ai_protocol: 0, ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
		var resultList = UnsafeMutablePointer<addrinfo>(bitPattern: 0)
		var result = getaddrinfo(host, nil, &hints, &resultList)
		while EAI_AGAIN == result {
			Threading.sleep(seconds: 0.1)
			result = getaddrinfo(host, nil, &hints, &resultList)
		}
		if result == EAI_NONAME {
			hints = addrinfo(ai_flags: aiFlags, ai_family: AF_INET6, ai_socktype: SOCK_STREAM, ai_protocol: 0, ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
			result = getaddrinfo(host, nil, &hints, &resultList)
		}
		if result == 0, var resultList = resultList {
			defer {
				freeaddrinfo(resultList)
			}
			guard let addr = resultList.pointee.ai_addr else {
				return -1
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
				return -1
			}
		} else {
			
			print("Result: \(result)")
			
			return -1
		}
		return 0
	}
	
	private final func completeArray(from frm: ReferenceBuffer, count: Int) -> [UInt8] {
		frm.a.removeLast(frm.size - count)
		return frm.a
	}
	
	func readBytesFully(into buffer: ReferenceBuffer, read: Int, remaining: Int, timeoutSeconds: Double, completion: @escaping ([UInt8]?) -> ()) {
		let readCount = recv(into: buffer[read], count: remaining)
		if readCount == 0 {
			completion(nil) // disconnect
		} else if self.isEAgain(err: readCount) {
			
			// no data available. wait
			self.readBytesFullyIncomplete(into: buffer, read: read, remaining: remaining, timeoutSeconds: timeoutSeconds, completion: completion)
			
		} else if readCount < 0 {
			completion(nil) // networking or other error
		} else {
			
			// got some data
			if remaining - readCount == 0 { // done
				completion(completeArray(from: buffer, count: read + readCount))
			} else { // try again for more
				readBytesFully(into: buffer, read: read + readCount, remaining: remaining - readCount, timeoutSeconds: timeoutSeconds, completion: completion)
			}
		}
	}
	
	func readBytesFullyIncomplete(into to: ReferenceBuffer, read: Int, remaining: Int, timeoutSeconds: Double, completion: @escaping ([UInt8]?) -> ()) {
		
		NetEvent.add(socket: fd.fd, what: .read, timeoutSeconds: timeoutSeconds) { [weak self]
			fd, w in
			
			if case .read = w {
				self?.readBytesFully(into: to, read: read, remaining: remaining, timeoutSeconds: timeoutSeconds, completion: completion)
			} else {
				completion(nil) // timeout or error
			}
		}
	}
	
	/// Read the indicated number of bytes and deliver them on the provided callback.
	/// - parameter count: The number of bytes to read
	/// - parameter timeoutSeconds: The number of seconds to wait for the requested number of bytes. A timeout value of negative one indicates that the request should have no timeout.
	/// - parameter completion: The callback on which the results will be delivered. If the timeout occurs before the requested number of bytes have been read, a nil object will be delivered to the callback.
	public func readBytesFully(count cnt: Int, timeoutSeconds: Double, completion: @escaping ([UInt8]?) -> ()) {

		let ptr = ReferenceBuffer(size: cnt)
		readBytesFully(into: ptr, read: 0, remaining: cnt, timeoutSeconds: timeoutSeconds, completion: completion)
	}
	
	/// Read up to the indicated number of bytes and deliver them on the provided callback.
	/// - parameter count: The maximum number of bytes to read.
	/// - parameter completion: The callback on which to deliver the results. If an error occurs during the read then a nil object will be passed to the callback, otherwise, the immediately available number of bytes, which may be zero, will be passed.
	public func readSomeBytes(count cnt: Int, completion: @escaping ([UInt8]?) -> ()) {
		
		let readRead = min(cnt, self.reasonableMaxReadCount)
		let ptr = ReferenceBuffer(size: readRead)
		let readCount = recv(into: ptr[0], count: readRead)
		if readCount == 0 {
			completion(nil)
		} else if self.isEAgain(err: readCount) {
			completion([UInt8]())
		} else if readCount == -1 {
			completion(nil)
		} else {
			let complete = completeArray(from: ptr, count: readCount)
			completion(complete)
		}
	}
	
	/// Write the string and call the callback with the number of bytes which were written.
	/// - parameter s: The string to write. The string will be written based on its UTF-8 encoding.
	/// - parameter completion: The callback which will be called once the write has completed. The callback will be passed the number of bytes which were successfuly written, which may be zero.
	public func write(string strng: String, completion: @escaping (Int) -> ()) {
		write(bytes: [UInt8](strng.utf8), completion: completion)
	}
	
	/// Write the indicated bytes and call the callback with the number of bytes which were written.
	/// - parameter bytes: The array of UInt8 to write.
	/// - parameter completion: The callback which will be called once the write has completed. The callback will be passed the number of bytes which were successfuly written, which may be zero.
	public func write(bytes byts: [UInt8], completion: @escaping (Int) -> ()) {
		write(bytes: byts, offsetBy: 0, count: byts.count, completion: completion)
	}
	
	/// Write the indicated bytes and return true if all data was sent.
	/// - parameter bytes: The array of UInt8 to write.
	public func writeFully(bytes byts: [UInt8]) -> Bool {
		let length = byts.count
		var totalSent = 0
		var s: Threading.Event?
		var what: NetEvent.Filter = .none
		
		let waitFunc = {
			NetEvent.add(socket: self.fd.fd, what: .write, timeoutSeconds: NetEvent.noTimeout) {
				_, w in
				what = w
				let _ = s?.lock()
				let _ = s?.signal()
				let _ = s?.unlock()
			}
		}
		
		while length > 0 {
			
			let sent = send(byts, offsetBy: totalSent, count: length - totalSent)
			if sent == length {
				return true
			}
			
			if s == nil {
				s = Threading.Event()
			}
			
			if sent == -1 {
				if isEAgain(err: sent) { // flow
					let _ = s!.lock()
					waitFunc()
				} else { // error
					break
				}
			} else {
				totalSent += sent
				
				if totalSent == length {
					return true
				}
				let _ = s!.lock()
				waitFunc()
			}
			
			let _ = s!.wait()
			let _ = s!.unlock()
			if case .write = what {
			
			} else {
				break
			}
		}
		return totalSent == length
	}
			 
	/// Write the indicated bytes and call the callback with the number of bytes which were written.
	/// - parameter bytes: The array of UInt8 to write.
	/// - parameter offsetBy: The offset within `bytes` at which to begin writing.
	/// - parameter count: The number of bytes to write.
	/// - parameter completion: The callback which will be called once the write has completed. The callback will be passed the number of bytes which were successfuly written, which may be zero.
	public func write(bytes: [UInt8], offsetBy: Int, count: Int, completion: @escaping (Int) -> ()) {
		let sent = send(bytes, offsetBy: offsetBy, count: count)
		if isEAgain(err: sent) {
			writeIncomplete(bytes: bytes, offsetBy: offsetBy, count: count, completion: completion)
		} else if sent == -1 {
			completion(sent)
		} else if sent < count {
			// flow control
			writeIncomplete(bytes: bytes, offsetBy: offsetBy + sent, count: count - sent, completion: completion)
		} else {
			completion(offsetBy + sent)
		}
	}
	
	func writeIncomplete(bytes: [UInt8], offsetBy: Int, count: Int, completion: @escaping (Int) -> ()) {
		NetEvent.add(socket: fd.fd, what: .write, timeoutSeconds: NetEvent.noTimeout) {
			fd, w in
			self.write(bytes: bytes, offsetBy: offsetBy, count: count, completion: completion)
		}
	}
	
	/// Connect to the indicated server
	/// - parameter address: The server's address, expressed as a string.
	/// - parameter port: The port on which to connect.
	/// - parameter timeoutSeconds: The number of seconds to wait for the connection to complete. A timeout of negative one indicates that there is no timeout.
	/// - parameter callBack: The closure which will be called when the connection completes. If the connection completes successfully then the current NetTCP instance will be passed to the callback, otherwise, a nil object will be passed.
	/// - returns: `PerfectError.NetworkError`
	public func connect(address addrs: String, port: UInt16, timeoutSeconds: Double, callBack: @escaping (NetTCP?) -> ()) throws {
		var addr = sockaddr_storage()
		let res = makeAddress(&addr, host: addrs, port: port)
		guard res != -1 else {
			try ThrowNetworkError()
		}
		initSocket(family: Int32(addr.ss_family))
		
//		let i0 = Int8(0)
//	#if os(Linux)
//		var sock_addr = sockaddr(sa_family: 0, sa_data: (i0, i0, i0, i0, i0, i0, i0, i0, i0, i0, i0, i0, i0, i0))
//	#else
//		var sock_addr = sockaddr(sa_len: 0, sa_family: 0, sa_data: (i0, i0, i0, i0, i0, i0, i0, i0, i0, i0, i0, i0, i0, i0))
//	#endif
//		memcpy(&sock_addr, &addr, Int(MemoryLayout<sockaddr_in>.size))
		
		let cRes: Int32 = UnsafeMutablePointer(&addr).withMemoryRebound(to: sockaddr.self, capacity: 1) {
			saddr in
		#if os(Linux)
			return SwiftGlibc.connect(self.fd.fd, saddr, socklen_t(addr.ss_len))
		#else
			return Darwin.connect(self.fd.fd, saddr, socklen_t(addr.ss_len))
		#endif
		}
		if cRes != -1 {
			callBack(self)
		} else {
			guard errno == EINPROGRESS else {
				try ThrowNetworkError()
			}
			NetEvent.add(socket: fd.fd, what: .write, timeoutSeconds: timeoutSeconds) {
				fd, w in
				if case .timer = w {
					callBack(nil)
				} else {
					callBack(self)
				}
			}
		}
	}
	
	/// Accept a new client connection and pass the result to the callback.
	/// - parameter timeoutSeconds: The number of seconds to wait for a new connection to arrive. A timeout value of negative one indicates that there is no timeout.
	/// - parameter callBack: The closure which will be called when the accept completes. the parameter will be a newly allocated instance of NetTCP which represents the client.
	/// - returns: `PerfectError.NetworkError`
	public func accept(timeoutSeconds timeout: Double, callBack: @escaping (NetTCP?) -> ()) throws {
	#if os(Linux)
		let accRes = SwiftGlibc.accept(fd.fd, nil, nil)
	#else
		let accRes = Darwin.accept(fd.fd, nil, nil)
	#endif
		if accRes != -1 {
			let newTcp = self.makeFromFd(accRes)
			return callBack(newTcp)
		}
        guard self.isEAgain(err: Int(accRes)) else {
            try ThrowNetworkError()
        }
        NetEvent.add(socket: fd.fd, what: .read, timeoutSeconds: timeout) {
            fd, w in
            if case .timer = w {
                return callBack(nil)
            }
            do {
                try self.accept(timeoutSeconds: timeout, callBack: callBack)
            } catch {
                callBack(nil)
            }
        }
	}
	
	private func tryAccept() -> Int32 {
    #if os(Linux)
        let accRes = SwiftGlibc.accept(fd.fd, nil, nil)
    #else
        let accRes = Darwin.accept(fd.fd, nil, nil)
    #endif
		return accRes
	}
	
	/// Accept a series of new client connections and pass them to the callback. This function does not return outside of a catastrophic error.
	/// - parameter callBack: The closure which will be called when the accept completes. the parameter will be a newly allocated instance of NetTCP which represents the client.
	public func forEachAccept(callBack: @escaping (NetTCP?) -> ()) {
		self.fd.switchToBlocking()
		repeat {
			let accRes = tryAccept()
			if accRes != -1 {
				Threading.dispatch {
					callBack(self.makeFromFd(accRes))
				}
			} else if errno != EINTR {
				let errStr = String(validatingUTF8: strerror(Int32(errno))) ?? "NO MESSAGE"
				print("Unexpected networking error: \(errno) '\(errStr)'")
				networkFailure = true
			}
		} while !networkFailure && self.fd.fd != invalidSocket
	}
	
	func makeFromFd(_ fd: Int32) -> NetTCP {
		return NetTCP(fd: fd)
	}
}





