//
//  NetTCPSSL.swift
//  PerfectLib
//
//  Created by Kyle Jessup on 2015-09-23.
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

import COpenSSL
import PerfectCrypto

#if os(Linux)
	import SwiftGlibc
#else
	import Darwin
#endif

private typealias passwordCallbackFunc = @convention(c) (UnsafeMutablePointer<Int8>?, Int32, Int32, UnsafeMutableRawPointer?) -> Int32
public typealias VerifyCACallbackFunc = @convention (c) (Int32, UnsafeMutablePointer<X509_STORE_CTX>?) -> Int32

public struct OpenSSLVerifyMode: OptionSet {
  public let rawValue: Int32
  public init(rawValue: Int32) {
    self.rawValue = rawValue
  }
  public static let sslVerifyNone = OpenSSLVerifyMode(rawValue: SSL_VERIFY_NONE)
  public static let sslVerifyPeer = OpenSSLVerifyMode(rawValue: SSL_VERIFY_PEER)
  public static let sslVerifyFailIfNoPeerCert = OpenSSLVerifyMode(rawValue: SSL_VERIFY_FAIL_IF_NO_PEER_CERT)
  public static let sslVerifyClientOnce = OpenSSLVerifyMode(rawValue: SSL_VERIFY_CLIENT_ONCE)
  public static let sslVerifyPeerWithFailIfNoPeerCert: OpenSSLVerifyMode = [.sslVerifyPeer, .sslVerifyFailIfNoPeerCert]
  public static let sslVerifyPeerClientOnce: OpenSSLVerifyMode = [.sslVerifyPeer, .sslVerifyClientOnce]
  public static let sslVerifyPeerWithFailIfNoPeerCertClientOnce: OpenSSLVerifyMode = [.sslVerifyPeer, .sslVerifyFailIfNoPeerCert, .sslVerifyClientOnce]
}

public enum TLSMethod {
	case tlsV1
	case tlsV1_1
	case tlsV1_2
}

public class NetTCPSSL : NetTCP {

	public static var opensslVersionText : String {
		return OPENSSL_VERSION_TEXT
	}
	public static var opensslVersionNumber : Int {
		return OPENSSL_VERSION_NUMBER
	}

	public class X509 {

		private let ptr: UnsafeMutablePointer<COpenSSL.X509>

		init(ptr: UnsafeMutablePointer<COpenSSL.X509>) {
			self.ptr = ptr
		}

		deinit {
			X509_free(self.ptr)
		}

		public var publicKeyBytes: [UInt8] {
			let pk = X509_get_pubkey(self.ptr)
			let len = Int(i2d_PUBKEY(pk, nil))
			var mp = UnsafeMutablePointer<UInt8>(nil as OpaquePointer?)

			i2d_PUBKEY(pk, &mp)

			var ret = [UInt8]()
			guard let ensure = mp else {
				return ret
			}
			defer {
				free(mp)
				EVP_PKEY_free(pk)
			}

			ret.reserveCapacity(len)
			for b in 0..<len {
				ret.append(ensure[b])
			}

			return ret
		}
	}

    static var initOnce: Bool = {
		guard PerfectCrypto.isInitialized else {
			return false
		}
        SSL_library_init()
        ERR_load_crypto_strings()
        SSL_load_error_strings()
        return true
    }()

	private var sharedSSLCtx = true
	fileprivate var sslCtx: UnsafeMutablePointer<SSL_CTX>?
	fileprivate var ssl: UnsafeMutablePointer<SSL>?

	public var tlsMethod: TLSMethod = .tlsV1_2
	
	fileprivate var alpnBuffer: [UInt8]?
	/// If ALPN is used, this will be the negotiated protocol for this accepted socket.
	/// This will be nil if ALPN is not enabled OR if the client and server share no common protocols.
	public var alpnNegotiated: String?
	
	public var keyFilePassword: String = "" {
		didSet {
			
		}
	}

	public var peerCertificate: X509? {
		guard let ssl = self.ssl else {
			return nil
		}
		guard let cert = SSL_get_peer_certificate(ssl) else {
			return nil
		}
		return X509(ptr: cert)
	}

	public var cipherList: [String] {
		get {
			var a = [String]()
			guard let ssl = self.ssl else {
				return a
			}
			var i = Int32(0)
			while true {
				guard let n = SSL_get_cipher_list(ssl, i) else {
					break
				}
				a.append(String(validatingUTF8: n)!)
				i += 1
			}
			return a
		}
		set(list) {
			let listStr = list.joined(separator: ",")
			if let ctx = self.sslCtx {
				if 0 == SSL_CTX_set_cipher_list(ctx, listStr) {
					print("SSL_CTX_set_cipher_list failed: \(self.errorStr(forCode: Int32(self.errorCode())))")
				}
			}
			if let ssl = self.ssl {
				if 0 == SSL_set_cipher_list(ssl, listStr) {
					print("SSL_CTX_set_cipher_list failed: \(self.errorStr(forCode: Int32(self.errorCode())))")
				}
			}
		}
	}

	public var initializedCallback: ((NetTCPSSL) -> ())?
	
	public func setTmpDH(path: String) -> Bool {
		guard let ctx = self.sslCtx,
			let bio = BIO_new_file(path, "r") else {
			return false
		}
		defer {
			BIO_free(bio)
		}
		guard let dh = PEM_read_bio_DHparams(bio, nil, nil, nil) else {
			return false
		}
		defer {
			DH_free(dh)
		}
		SSL_CTX_ctrl(ctx, SSL_CTRL_SET_TMP_DH, 0, dh)
		return true
	}

	public var usingSSL: Bool {
		return self.ssl != nil
	}

	public override init() {
		super.init()
		_ = NetTCPSSL.initOnce
	}
	
	func passwordCallback(_ buf:UnsafeMutablePointer<Int8>, size:Int32, rwflag:Int32) -> Int32 {
		let chars = self.keyFilePassword.utf8
		memmove(buf, self.keyFilePassword, chars.count + 1)
		return Int32(chars.count)
	}
	
	override public func initSocket(family: Int32) {
		super.initSocket(family: family)
		guard self.sslCtx == nil else {
			return
		}

		switch self.tlsMethod {
		case .tlsV1_2: self.sslCtx = SSL_CTX_new(TLSv1_2_method())
		case .tlsV1_1: self.sslCtx = SSL_CTX_new(TLSv1_1_method())
		case .tlsV1: self.sslCtx = SSL_CTX_new(TLSv1_method())
		}
		
		guard let sslCtx = self.sslCtx else {
			return
		}
		self.sharedSSLCtx = false
	#if os(Linux)
		if openssl_compat_have_ecdh_auto == 1 {
			SSL_CTX_ctrl(sslCtx, SSL_CTRL_SET_ECDH_AUTO, 1, nil)
		}
	#else
		SSL_CTX_ctrl(sslCtx, SSL_CTRL_SET_ECDH_AUTO, 1, nil)
	#endif
		SSL_CTX_ctrl(sslCtx, SSL_CTRL_MODE, SSL_MODE_AUTO_RETRY, nil)
		SSL_CTX_ctrl(sslCtx, SSL_CTRL_OPTIONS, SSL_OP_ALL, nil)
		
		initializedCallback?(self)
		
		if !keyFilePassword.isEmpty {
			let opaqueMe = Unmanaged.passUnretained(self).toOpaque()
			let callback: passwordCallbackFunc = {
				(buf, size, rwflag, userData) -> Int32 in
				
				guard let userDataCheck = userData, let bufCheck = buf else {
					return 0
				}
				let crl = Unmanaged<NetTCPSSL>.fromOpaque(UnsafeMutableRawPointer(userDataCheck)).takeUnretainedValue()
				return crl.passwordCallback(bufCheck, size: size, rwflag: rwflag)
			}
			SSL_CTX_set_default_passwd_cb_userdata(self.sslCtx!, opaqueMe)
			SSL_CTX_set_default_passwd_cb(self.sslCtx!, callback)
		}
	}

	public func errorCode() -> UInt {
		let err = ERR_get_error()
		return err
	}

	public func sslErrorCode(resultCode code: Int32) -> Int32 {
		if let ssl = self.ssl {
			let err = SSL_get_error(ssl, code)
			return err
		}
		return -1
	}

	public func errorStr(forCode errorCode: Int32) -> String {
		let maxLen = 1024
        let buf = UnsafeMutablePointer<Int8>.allocate(capacity: maxLen)
		defer {
			buf.deallocate(capacity: maxLen)
		}
		ERR_error_string_n(UInt(errorCode), buf, maxLen)
		let ret = String(validatingUTF8: buf) ?? ""
		return ret
	}

	public func reasonErrorStr(errorCode: Int32) -> String {
		guard let buf = ERR_reason_error_string(UInt(errorCode)) else {
			return ""
		}
		let ret = String(validatingUTF8: buf) ?? ""
		return ret
	}

	override func isEAgain(err er: Int) -> Bool {
		if er == -1 && self.usingSSL {
			let sslErr = SSL_get_error(self.ssl!, Int32(er))
			if sslErr != SSL_ERROR_SYSCALL {
				return sslErr == SSL_ERROR_WANT_READ || sslErr == SSL_ERROR_WANT_WRITE
			}
		}
		return super.isEAgain(err: er)
	}

	override func recv(into buf: UnsafeMutableRawPointer, count: Int) -> Int {
		if self.usingSSL {
			let i = Int(SSL_read(self.ssl!, buf, Int32(count)))
			return i
		}
		return super.recv(into: buf, count: count)
	}

	override func send(_ buf: [UInt8], offsetBy: Int, count: Int) -> Int {
		let ptr = UnsafeRawPointer(buf).advanced(by: offsetBy)
		if self.usingSSL {
			let i = Int(SSL_write(self.ssl!, ptr, Int32(count)))
			return i
		}
		return super.send(buf, offsetBy: offsetBy, count: count)
	}

	override func readBytesFullyIncomplete(into to: ReferenceBuffer, read: Int, remaining: Int, timeoutSeconds: Double, completion: @escaping ([UInt8]?) -> ()) {
		guard usingSSL else {
			return super.readBytesFullyIncomplete(into: to, read: read, remaining: remaining, timeoutSeconds: timeoutSeconds, completion: completion)
		}
		var what = NetEvent.Filter.write
		let sslErr = SSL_get_error(self.ssl!, -1)
		if sslErr == SSL_ERROR_WANT_READ {
			what = NetEvent.Filter.read
		}

		NetEvent.add(socket: fd.fd, what: what, timeoutSeconds: NetEvent.noTimeout) {
			fd, w in

			if case .timer = w {
				completion(nil) // timeout or error
			} else {
				self.readBytesFully(into: to, read: read, remaining: remaining, timeoutSeconds: timeoutSeconds, completion: completion)
			}
		}
	}

	override func writeIncomplete(bytes: [UInt8], offsetBy: Int, count: Int, completion: @escaping (Int) -> ()) {
		guard usingSSL else {
			return super.writeIncomplete(bytes: bytes, offsetBy: offsetBy, count: count, completion: completion)
		}
		var what = NetEvent.Filter.write
		let sslErr = SSL_get_error(self.ssl!, -1)
		if sslErr == SSL_ERROR_WANT_READ {
			what = NetEvent.Filter.read
		}

		NetEvent.add(socket: fd.fd, what: what, timeoutSeconds: NetEvent.noTimeout) { [weak self]
			fd, w in
			self?.write(bytes: bytes, offsetBy: offsetBy, count: count, completion: completion)
		}
	}

	public override func close() {
		if let ssl = self.ssl {
			SSL_shutdown(ssl)
			SSL_free(ssl)
			self.ssl = nil
		}
		if let sslCtx = self.sslCtx, self.sharedSSLCtx == false {
			SSL_CTX_free(sslCtx)
		}
		self.sslCtx = nil
		super.close()
	}

	public func beginSSL(closure: @escaping (Bool) -> ()) {
		self.beginSSL(timeoutSeconds: 5.0, closure: closure)
	}

	public func beginSSL(timeoutSeconds timeout: Double, closure: @escaping (Bool) -> ()) {
		guard self.fd.fd != invalidSocket else {
			closure(false)
			return
		}

		if self.ssl == nil {
			self.ssl = SSL_new(self.sslCtx!)
			SSL_set_fd(self.ssl!, self.fd.fd)
		}

		guard let ssl = self.ssl else {
			closure(false)
			return
		}

		let res = SSL_connect(ssl)
		switch res {
		case 1:
			closure(true)
		case 0:
			closure(false)
		case -1:
			let sslErr = SSL_get_error(ssl, res)
			if sslErr == SSL_ERROR_WANT_WRITE {

				NetEvent.add(socket: fd.fd, what: .write, timeoutSeconds: timeout) { [weak self]
					fd, w in

					if case .write = w {
						self?.beginSSL(timeoutSeconds: timeout, closure: closure)
					} else {
						closure(false)
					}
				}
				return
			} else if sslErr == SSL_ERROR_WANT_READ {

				NetEvent.add(socket: fd.fd, what: .read, timeoutSeconds: timeout) { [weak self]
					fd, w in

					if case .read = w {
						self?.beginSSL(timeoutSeconds: timeout, closure: closure)
					} else {
						closure(false)
					}
				}
				return
			} else {
				closure(false)
			}
		default:
			closure(false)
		}
	}

	public func endSSL() {
		if let ssl = self.ssl {
			SSL_free(ssl)
			self.ssl = nil
		}
		if let sslCtx = self.sslCtx {
			SSL_CTX_free(sslCtx)
			self.sslCtx = nil
		}
	}

	override public func shutdown() {
		if let ssl = self.ssl {
			SSL_shutdown(ssl)
		}
		super.shutdown()
	}

	public func setConnectState() {
		if let ssl = self.ssl {
			SSL_set_connect_state(ssl)
		}
	}

	public func setAcceptState() {
		if let ssl = self.ssl {
			SSL_set_accept_state(ssl)
		}
	}

	public func setDefaultVerifyPaths() -> Bool {
		guard let sslCtx = self.sslCtx else {
			return false
		}
		let r = SSL_CTX_set_default_verify_paths(sslCtx)
		return r == 1
	}

	public func setVerifyLocations(caFilePath: String, caDirPath: String) -> Bool {
		guard let sslCtx = self.sslCtx else {
			return false
		}
		let r = SSL_CTX_load_verify_locations(sslCtx, caFilePath, caDirPath)
		return r == 1
	}

	public func useCertificateFile(cert: String) -> Bool {
		guard let sslCtx = self.sslCtx else {
			return false
		}
		let r = SSL_CTX_use_certificate_file(sslCtx, cert, SSL_FILETYPE_PEM)
		return r == 1
	}

	public func useCertificateChainFile(cert crt: String) -> Bool {
		guard let sslCtx = self.sslCtx else {
			return false
		}
		let r = SSL_CTX_use_certificate_chain_file(sslCtx, crt)
		return r == 1
	}

	public func useCertificateChain(cert crt: String) -> Bool {
		guard let sslCtx = self.sslCtx else {
			return false
		}
		let bio = BIO_new(BIO_s_mem())
		defer {
			BIO_free(bio)
		}
		BIO_puts(bio, crt)
		let certificate = PEM_read_bio_X509(bio, nil, nil, nil)
		let r = SSL_CTX_use_certificate(sslCtx, certificate)
		return r == 1
	}

	public func usePrivateKeyFile(cert crt: String) -> Bool {
		guard let sslCtx = self.sslCtx else {
			return false
		}
		let r = SSL_CTX_use_PrivateKey_file(sslCtx, crt, SSL_FILETYPE_PEM)
		return r == 1
	}

	/// Use a stringified version of the certificate.
	public func usePrivateKey(cert crt: String) -> Bool {
		guard let sslCtx = self.sslCtx else {
			return false
		}
		let bio = BIO_new(BIO_s_mem())
		defer {
			BIO_free(bio)
		}
		BIO_puts(bio, crt)
		let pKey = PEM_read_bio_PrivateKey(bio, nil, nil, nil)
		let r = SSL_CTX_use_PrivateKey(sslCtx, pKey)
		return r == 1
	}

	public func checkPrivateKey() -> Bool {
		guard let sslCtx = self.sslCtx else {
			return false
		}
		let r = SSL_CTX_check_private_key(sslCtx)
		return r == 1
	}
  
	public func setClientCA(path: String, verifyMode: OpenSSLVerifyMode) -> Bool {
		guard let sslCtx = self.sslCtx else {
			return false
		}

		let oldList = SSL_CTX_get_client_CA_list(sslCtx)
		SSL_CTX_set_client_CA_list(sslCtx, SSL_load_client_CA_file(path))
		let newList = SSL_CTX_get_client_CA_list(sslCtx)

		if
			let oldNbCAs = oldList?.pointee.stack.num,
			let newNbCAs = newList?.pointee.stack.num, oldNbCAs + 1 == newNbCAs {

			SSL_CTX_set_verify(sslCtx, verifyMode.rawValue, nil)
			return true
		}
		return false
	}

	public func subscribeCAVerify(verifyMode: OpenSSLVerifyMode,
							callback: @escaping VerifyCACallbackFunc) {
		SSL_CTX_set_verify(sslCtx, verifyMode.rawValue, callback)
	}

	override func makeFromFd(_ fd: Int32) -> NetTCP {
		return NetTCPSSL(fd: fd)
	}
	
	override public func connect(address addrs: String, port: UInt16, timeoutSeconds: Double, callBack: @escaping (NetTCP?) -> ()) throws {
		_ = setDefaultVerifyPaths()
		try super.connect(address: addrs, port: port, timeoutSeconds: timeoutSeconds) {
			net in
			guard let netSSL = net as? NetTCPSSL else {
				return callBack(net)
			}
			netSSL.beginSSL {
				success in
				guard success else {
					netSSL.close()
					return callBack(nil)
				}
				if nil != netSSL.alpnBuffer {
					netSSL.finalizeALPNClient()
				}
				callBack(netSSL)
			}
		}
	}

	override public func forEachAccept(callBack: @escaping (NetTCP?) -> ()) {
		super.forEachAccept {
			[unowned self] (net:NetTCP?) -> () in

			if let netSSL = net as? NetTCPSSL {

				netSSL.sslCtx = self.sslCtx
				netSSL.ssl = SSL_new(self.sslCtx!)
				SSL_set_fd(netSSL.ssl!, netSSL.fd.fd)
				netSSL.alpnBuffer = self.alpnBuffer
				netSSL.enableALPN()
				self.finishAccept(timeoutSeconds: -1, net: netSSL, callBack: callBack)
			} else {
				callBack(net)
			}
		}
	}

	override public func accept(timeoutSeconds timeout: Double, callBack: @escaping (NetTCP?) -> ()) throws {
		try super.accept(timeoutSeconds: timeout, callBack: {
			[unowned self] (net:NetTCP?) -> () in

			if let netSSL = net as? NetTCPSSL {

				netSSL.sslCtx = self.sslCtx
				netSSL.ssl = SSL_new(self.sslCtx!)
				SSL_set_fd(netSSL.ssl!, netSSL.fd.fd)
				netSSL.alpnBuffer = self.alpnBuffer
				netSSL.enableALPN()
				self.finishAccept(timeoutSeconds: timeout, net: netSSL, callBack: callBack)
			} else {
				callBack(net)
			}
		})
	}

	func finishAccept(timeoutSeconds timeout: Double, net: NetTCPSSL, callBack: @escaping (NetTCP?) -> ()) {
		let res = SSL_accept(net.ssl!)
		let sslErr = SSL_get_error(net.ssl!, res)
		if res == -1 {
			if sslErr == SSL_ERROR_WANT_WRITE {

				NetEvent.add(socket: net.fd.fd, what: .write, timeoutSeconds: timeout) { [weak self]
					fd, w in

					if case .timer = w {
						callBack(nil)
					} else {
						self?.finishAccept(timeoutSeconds: timeout, net: net, callBack: callBack)
					}
				}

			} else if sslErr == SSL_ERROR_WANT_READ {

				NetEvent.add(socket: net.fd.fd, what: .read, timeoutSeconds: timeout) { [weak self]
					fd, w in

					if case .timer = w {
						callBack(nil)
					} else {
						self?.finishAccept(timeoutSeconds: timeout, net: net, callBack: callBack)
					}
				}

			} else {
				callBack(nil)
			}
		} else {
			callBack(net)
		}
	}
}

extension NetTCPSSL {
	/// Given a list of protocol names, such as h2, http/1.1, this will enable ALPN protocol selection.
	/// The name of the server+client matched protocol will be available in the `.alpnNegotiated` property.
	/// This protocol list can be set on the server or client socket. Accepted/connected sockets 
	/// will have `.alpnNegotiated` set to the negotiated protocol.
	public func enableALPN(protocols: [String]) {
		let buffer: [UInt8] = protocols.map { Array($0.utf8) }
			.map { [UInt8($0.count)] + $0 }
			.reduce([], +)
		
		alpnBuffer = buffer
		enableALPN()
	}
	
	func enableALPN() {
		enableALPNServer()
		enableALPNClient()
	}
	
	func enableALPNServer() {
		guard let ctx = self.sslCtx else {
			return
		}
		typealias alpnSelectCallbackFunc = @convention(c) (UnsafeMutablePointer<SSL>?, UnsafeMutablePointer<UnsafePointer<UInt8>?>?, UnsafeMutablePointer<UInt8>?, UnsafePointer<UInt8>?, UInt32, UnsafeMutableRawPointer?) -> Int32
		let callback: alpnSelectCallbackFunc = {
			(ssl: UnsafeMutablePointer<SSL>?,
			outBuf: UnsafeMutablePointer<UnsafePointer<UInt8>?>?,
			outLen: UnsafeMutablePointer<UInt8>?,
			clientBuf: UnsafePointer<UInt8>?,
			clientLen: UInt32,
			userData: UnsafeMutableRawPointer?) -> Int32 in
			
			guard let userDataCheck = userData else {
				return OPENSSL_NPN_NO_OVERLAP
			}
			
			let itsame = Unmanaged<NetTCPSSL>.fromOpaque(UnsafeMutableRawPointer(userDataCheck)).takeUnretainedValue()
			
			guard let serverBuf = itsame.alpnBuffer,
				let clientBuf = clientBuf,
				let outBuf = outBuf else {
					return OPENSSL_NPN_NO_OVERLAP
			}
			
			let serverLen = UInt32(serverBuf.count)
			return outBuf.withMemoryRebound(to: UnsafeMutablePointer<UInt8>?.self, capacity: 1) {
				outBuf in
				let result = SSL_select_next_proto(outBuf, outLen,
				                                   serverBuf, serverLen,
				                                   clientBuf, clientLen)
				if result == OPENSSL_NPN_NEGOTIATED, let chars = outBuf.pointee, let len = outLen?.pointee {
					var selectedChars = [UInt8]()
					for n in 0..<Int(len) {
						selectedChars.append(chars[n])
					}
					let negotiated = String(validatingUTF8: selectedChars)
					itsame.alpnNegotiated = negotiated
					return SSL_TLSEXT_ERR_OK
				}
				return SSL_TLSEXT_ERR_NOACK
			}
		}
		let opaqueMe = Unmanaged.passUnretained(self).toOpaque()
		SSL_CTX_set_alpn_select_cb(ctx, callback, opaqueMe)
	}
	
	func enableALPNClient() {
		guard let ctx = self.sslCtx, let clientBuf = alpnBuffer else {
			return
		}
		SSL_CTX_set_alpn_protos(ctx, clientBuf, UInt32(clientBuf.count))
	}
	
	func finalizeALPNClient() {
		var ptr: UnsafePointer<UInt8>?  = nil
		var len: UInt32 = 0
		SSL_get0_alpn_selected(ssl, &ptr, &len)
		if len > 0, let ptr = ptr {
			var selectedChars = [UInt8]()
			for n in 0..<Int(len) {
				selectedChars.append(ptr[n])
			}
			let negotiated = String(validatingUTF8: selectedChars)
			self.alpnNegotiated = negotiated
		}
	}
}







