import XCTest
@testable import PerfectNet
import PerfectThread

class PerfectNetTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
    }
	
    func testClientServer() {
        let port = UInt16(6500)
        do {
            let server = NetTCP()
            let client = NetTCP()
            try server.bind(port: port, address: "127.0.0.1")
            server.listen()
            let serverExpectation = self.expectation(description: "server")
            let clientExpectation = self.expectation(description: "client")
            try server.accept(timeoutSeconds: NetEvent.noTimeout) {
                (inn: NetTCP?) -> () in
                guard let n = inn else {
                    XCTAssertNotNil(inn)
                    return
                }
                let b = [UInt8(1)]
                do {
                    n.write(bytes: b) {
                        sent in
                        XCTAssertTrue(sent == 1)
                        n.readBytesFully(count: 1, timeoutSeconds: 5.0) {
                            read in
                            XCTAssert(read != nil)
                            XCTAssert(read?.count == 1)
                        }
                        serverExpectation.fulfill()
                    }
                }
            }
            
            try client.connect(address: "127.0.0.1", port: port, timeoutSeconds: 5) {
                (inn: NetTCP?) -> () in
                guard let n = inn else {
                    XCTAssertNotNil(inn)
                    return
                }
                let b = [UInt8(1)]
                do {
                    n.readBytesFully(count: 1, timeoutSeconds: 5.0) {
                        read in
                        XCTAssert(read != nil)
                        XCTAssert(read!.count == 1)
                        n.write(bytes: b) {
                            sent in
                            XCTAssertTrue(sent == 1)
                            clientExpectation.fulfill()
                        }
                    }
                }
            }
			self.waitForExpectations(timeout: 10000, handler: {
				_ in
				server.close()
				client.close()
			})
        } catch PerfectNetError.networkError(let code, let msg) {
            XCTAssert(false, "Exception: \(code) \(msg)")
        } catch let e {
            XCTAssert(false, "Exception: \(e)")
        }
    }

    func testClientServerReadTimeout() {
        let port = UInt16(6500)
        do {
            let server = NetTCP()
            let client = NetTCP()
            try server.bind(port: port, address: "127.0.0.1")
            server.listen()
            let serverExpectation = self.expectation(description: "server")
            let clientExpectation = self.expectation(description: "client")
            try server.accept(timeoutSeconds: NetEvent.noTimeout) {
                (inn: NetTCP?) -> () in
                guard let _ = inn else {
                    XCTAssertNotNil(inn)
                    return
                }
                Threading.sleep(seconds: 5)
                serverExpectation.fulfill()
            }
            var once = false
            try client.connect(address: "127.0.0.1", port: port, timeoutSeconds: 5) {
                (inn: NetTCP?) -> () in
                guard let n = inn else {
                    XCTAssertNotNil(inn)
                    return
                }
                do {
                    n.readBytesFully(count: 1, timeoutSeconds: 2.0) {
                        read in
                        XCTAssert(read == nil)
                        XCTAssert(once == false)
                        once = !once
                        Threading.sleep(seconds: 7)
                        XCTAssert(once == true)
                        clientExpectation.fulfill()
                    }
                }
            }
			self.waitForExpectations(timeout: 10000, handler: {
				_ in
				server.close()
				client.close()
			})
        } catch PerfectNetError.networkError(let code, let msg) {
            XCTAssert(false, "Exception: \(code) \(msg)")
        } catch let e {
            XCTAssert(false, "Exception: \(e)")
        }
    }
    
    func testTCPSSLClient() {
        let address = "www.treefrog.ca"
        let requestString = [UInt8](("GET / HTTP/1.0\r\nHost: \(address)\r\n\r\n").utf8)
        let requestCount = requestString.count
		let clientExpectation = self.expectation(description: "client")
        let net = NetTCPSSL()
        let setOk = net.setDefaultVerifyPaths()
        XCTAssert(setOk, "Unable to setDefaultVerifyPaths \(net.sslErrorCode(resultCode: 1))")
        do {
            try net.connect(address: address, port: 443, timeoutSeconds: 5.0) {
                net in
                if let ssl = net as? NetTCPSSL {
                    
                    ssl.beginSSL {
                        (success: Bool) in
                        
                        XCTAssert(success, "Unable to begin SSL \(ssl.errorStr(forCode: Int32(ssl.errorCode())))")
                        if !success {
                            clientExpectation.fulfill()
                            return
                        }
                        
                        do {
                            let x509 = ssl.peerCertificate
                            XCTAssert(x509 != nil)
                            let peerKey = x509?.publicKeyBytes
                            XCTAssert(peerKey != nil && peerKey!.count > 0)
                        }
                        
                        ssl.write(bytes: requestString) {
                            sent in
                            XCTAssert(sent == requestCount)
                            ssl.readBytesFully(count: 1, timeoutSeconds: 5.0) {
                                readBytes in
                                XCTAssert(readBytes != nil && readBytes!.count > 0)
                                var readBytesCpy = readBytes!
                                readBytesCpy.append(0)
                                let ptr = UnsafeRawPointer(readBytesCpy)
                                let s1 = String(validatingUTF8: ptr.assumingMemoryBound(to: CChar.self))!
                                ssl.readSomeBytes(count: 4096) {
                                    readBytes in
                                    XCTAssert(readBytes != nil && readBytes!.count > 0)
                                    var readBytesCpy = readBytes!
									readBytesCpy.append(0)
									let ptr = UnsafeRawPointer(readBytesCpy)
									let s2 = String(validatingUTF8: ptr.assumingMemoryBound(to: CChar.self))!
                                    let s = s1 + s2
                                    XCTAssert(s.characters.starts(with: "HTTP/1.1 200 OK".characters))
                                    clientExpectation.fulfill()
                                }
                            }
                        }
                    }
                } else {
                    XCTAssert(false, "Did not get NetTCPSSL back after connect")
                }
            }
        } catch {
            XCTAssert(false, "Exception thrown")
        }
		self.waitForExpectations(timeout: 10000) {
			_ in
			net.close()
		}
    }
    
    static var allTests : [(String, (PerfectNetTests) -> () throws -> Void)] {
        return [
            ("testClientServer", testClientServer),
            ("testClientServerReadTimeout", testClientServerReadTimeout),
            ("testTCPSSLClient", testTCPSSLClient)            
        ]
    }
}
