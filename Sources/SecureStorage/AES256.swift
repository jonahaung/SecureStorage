
import Foundation
import CommonCrypto

struct AES256 {
    
    private var key: Data
    private var IV: Data
    
    public init(key: Data, iv: Data) throws {
        guard key.count == kCCKeySizeAES256 else {
            throw Error.badKeyLength
        }
        guard iv.count == kCCBlockSizeAES128 else {
            throw Error.badInputVectorLength
        }
        self.key = key
        self.IV = iv
    }
    
    enum Error: Swift.Error {
        case keyGeneration(status: Int)
        case cryptoFailed(status: CCCryptorStatus)
        case badKeyLength
        case badInputVectorLength
    }
    
    func encrypt(_ digest: Data) throws -> Data {
        return try crypt(input: digest, operation: CCOperation(kCCEncrypt))
    }
    
    func decrypt(_ encrypted: Data) throws -> Data {
        return try crypt(input: encrypted, operation: CCOperation(kCCDecrypt))
    }
    
    private func crypt(input: Data, operation: CCOperation) throws -> Data {
        var outLength = Int(0)
        var outBytes = [UInt8](repeating: 0, count: input.count + kCCBlockSizeAES128)
        var status = CCCryptorStatus(kCCSuccess)
        input.withUnsafeBytes { (inputBuffer: UnsafeRawBufferPointer) in
            IV.withUnsafeBytes { (IVBuffer: UnsafeRawBufferPointer) in
                key.withUnsafeBytes { (keyBuffer: UnsafeRawBufferPointer) in
                    let inputBytes = inputBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self)
                    let IVBytes = IVBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self)
                    let keyBytes = keyBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self)
                    status = CCCrypt(
                        operation,
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionPKCS7Padding),
                        keyBytes,
                        key.count,
                        IVBytes,
                        inputBytes,
                        input.count,
                        &outBytes,
                        outBytes.count,
                        &outLength
                    )
                }
            }
        }
        guard status == kCCSuccess else {
            throw Error.cryptoFailed(status: status)
        }
        return Data(bytes: outBytes, count: outLength)
    }
    
    static func createKey(password: Data, salt: Data) throws -> Data {
        let length = kCCKeySizeAES256
        var status = Int32(0)
        var derivedBytes = [UInt8](repeating: 0, count: length)
        password.withUnsafeBytes { (passwordBuffer: UnsafeRawBufferPointer) in
            salt.withUnsafeBytes { (saltBuffer: UnsafeRawBufferPointer) in
                let passwordBytes = passwordBuffer.baseAddress?.assumingMemoryBound(to: Int8.self)
                let saltBytes = saltBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self)
                status = CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    passwordBytes,
                    password.count,
                    saltBytes,
                    salt.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1),
                    10000,
                    &derivedBytes,
                    length
                )
            }
        }
        guard status == 0 else {
            throw Error.keyGeneration(status: Int(status))
        }
        return Data(bytes: derivedBytes, count: length)
    }
    
    static func randomIV() -> Data {
        return randomData(length: kCCBlockSizeAES128)
    }
    
    static func randomSalt() -> Data {
        return randomData(length: 8)
    }
    
    static func randomData(length: Int) -> Data {
        var data = Data(count: length)
        let status = data.withUnsafeMutableBytes { buffer -> Int32 in
            if let bytes = buffer.baseAddress?.assumingMemoryBound(to: UInt8.self) {
                return SecRandomCopyBytes(kSecRandomDefault, length, bytes)
            }
            return -1
        }
        assert(status == Int32(0))
        return data
    }
}
