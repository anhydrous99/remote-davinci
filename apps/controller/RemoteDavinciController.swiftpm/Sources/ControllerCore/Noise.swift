import CryptoKit
import Foundation

enum NoiseError: LocalizedError {
    case invalidKey
    case invalidMessage
    case invalidState
    case messageTooLarge
    case nonceExhausted

    var errorDescription: String? {
        switch self {
        case .invalidKey: "Invalid Noise key"
        case .invalidMessage: "Invalid Noise message"
        case .invalidState: "Invalid Noise state"
        case .messageTooLarge: "Noise message is too large"
        case .nonceExhausted: "Noise nonce exhausted"
        }
    }
}

final class NoiseIKInitiator {
    static let protocolName = Data("Noise_IK_25519_ChaChaPoly_SHA256".utf8)
    static let maxPlaintextBytes = 16_368

    private enum Phase {
        case ready
        case waitingForResponse
        case transport
    }

    private let staticPrivateKey: Curve25519.KeyAgreement.PrivateKey
    private let remoteStaticKey: Curve25519.KeyAgreement.PublicKey
    private let suppliedEphemeralPrivateKey: Data?
    private var ephemeralPrivateKey: Curve25519.KeyAgreement.PrivateKey?
    private var symmetric: NoiseSymmetricState
    private var sendCipher: NoiseCipherState?
    private var receiveCipher: NoiseCipherState?
    private var phase = Phase.ready

    init(
        staticPrivateKey: Data,
        remoteStaticKey: Data,
        prologue: Data,
        ephemeralPrivateKey: Data? = nil
    ) throws {
        guard !remoteStaticKey.allSatisfy({ $0 == 0 }) else {
            throw NoiseError.invalidKey
        }
        self.staticPrivateKey = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: staticPrivateKey
        )
        self.remoteStaticKey = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: remoteStaticKey
        )
        suppliedEphemeralPrivateKey = ephemeralPrivateKey

        var state = NoiseSymmetricState(protocolName: Self.protocolName)
        state.mixHash(prologue)
        state.mixHash(remoteStaticKey)
        symmetric = state
    }

    func writeMessage1() throws -> Data {
        guard phase == .ready else { throw NoiseError.invalidState }

        let ephemeral: Curve25519.KeyAgreement.PrivateKey
        if let suppliedEphemeralPrivateKey {
            ephemeral = try Curve25519.KeyAgreement.PrivateKey(
                rawRepresentation: suppliedEphemeralPrivateKey
            )
        } else {
            ephemeral = Curve25519.KeyAgreement.PrivateKey()
        }
        ephemeralPrivateKey = ephemeral

        var message = Data()
        let ephemeralPublicKey = ephemeral.publicKey.rawRepresentation
        message.append(ephemeralPublicKey)
        symmetric.mixHash(ephemeralPublicKey)
        symmetric.mixKey(try noiseDH(ephemeral, remoteStaticKey))
        message.append(try symmetric.encryptAndHash(staticPrivateKey.publicKey.rawRepresentation))
        symmetric.mixKey(try noiseDH(staticPrivateKey, remoteStaticKey))
        message.append(try symmetric.encryptAndHash(Data()))

        phase = .waitingForResponse
        return message
    }

    func readMessage2(_ message: Data) throws {
        guard phase == .waitingForResponse,
              let ephemeralPrivateKey,
              message.count == 48
        else {
            throw NoiseError.invalidMessage
        }

        let remoteEphemeralBytes = Data(message.prefix(32))
        guard !remoteEphemeralBytes.allSatisfy({ $0 == 0 }) else {
            throw NoiseError.invalidKey
        }
        let remoteEphemeral = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: remoteEphemeralBytes
        )
        symmetric.mixHash(remoteEphemeralBytes)
        symmetric.mixKey(try noiseDH(ephemeralPrivateKey, remoteEphemeral))
        symmetric.mixKey(try noiseDH(staticPrivateKey, remoteEphemeral))
        guard try symmetric.decryptAndHash(Data(message.dropFirst(32))).isEmpty else {
            throw NoiseError.invalidMessage
        }

        (sendCipher, receiveCipher) = symmetric.split()
        phase = .transport
    }

    func encryptTransport(_ plaintext: Data) throws -> Data {
        guard phase == .transport, var cipher = sendCipher else {
            throw NoiseError.invalidState
        }
        guard plaintext.count <= Self.maxPlaintextBytes else {
            throw NoiseError.messageTooLarge
        }
        let ciphertext = try cipher.encrypt(ad: Data(), plaintext: plaintext)
        sendCipher = cipher
        return ciphertext
    }

    func decryptTransport(_ ciphertext: Data) throws -> Data {
        guard phase == .transport, var cipher = receiveCipher else {
            throw NoiseError.invalidState
        }
        guard ciphertext.count <= Self.maxPlaintextBytes + 16 else {
            throw NoiseError.messageTooLarge
        }
        let plaintext = try cipher.decrypt(ad: Data(), ciphertext: ciphertext)
        receiveCipher = cipher
        return plaintext
    }
}

final class NoiseNNpsk0Initiator {
    static let protocolName = Data("Noise_NNpsk0_25519_ChaChaPoly_SHA256".utf8)
    static let maxPlaintextBytes = 16_368

    private enum Phase {
        case ready
        case waitingForResponse
        case transport
    }

    private let psk: Data
    private let suppliedEphemeralPrivateKey: Data?
    private var ephemeralPrivateKey: Curve25519.KeyAgreement.PrivateKey?
    private var symmetric: NoiseSymmetricState
    private var sendCipher: NoiseCipherState?
    private var receiveCipher: NoiseCipherState?
    private var phase = Phase.ready

    init(psk: Data, prologue: Data, ephemeralPrivateKey: Data? = nil) throws {
        guard psk.count == 32 else { throw NoiseError.invalidKey }
        self.psk = psk
        suppliedEphemeralPrivateKey = ephemeralPrivateKey

        var state = NoiseSymmetricState(protocolName: Self.protocolName)
        state.mixHash(prologue)
        symmetric = state
    }

    func writeMessage1() throws -> Data {
        guard phase == .ready else { throw NoiseError.invalidState }

        let ephemeral: Curve25519.KeyAgreement.PrivateKey
        if let suppliedEphemeralPrivateKey {
            ephemeral = try Curve25519.KeyAgreement.PrivateKey(
                rawRepresentation: suppliedEphemeralPrivateKey
            )
        } else {
            ephemeral = Curve25519.KeyAgreement.PrivateKey()
        }
        ephemeralPrivateKey = ephemeral

        symmetric.mixKeyAndHash(psk)
        let publicKey = ephemeral.publicKey.rawRepresentation
        symmetric.mixHash(publicKey)
        symmetric.mixKey(publicKey)

        phase = .waitingForResponse
        return publicKey + (try symmetric.encryptAndHash(Data()))
    }

    func readMessage2(_ message: Data) throws {
        guard phase == .waitingForResponse,
              let ephemeralPrivateKey,
              message.count == 48
        else {
            throw NoiseError.invalidMessage
        }

        let remotePublicKeyData = Data(message.prefix(32))
        guard !remotePublicKeyData.allSatisfy({ $0 == 0 }) else {
            throw NoiseError.invalidKey
        }
        let remotePublicKey = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: remotePublicKeyData
        )
        symmetric.mixHash(remotePublicKeyData)
        symmetric.mixKey(remotePublicKeyData)
        symmetric.mixKey(try noiseDH(ephemeralPrivateKey, remotePublicKey))
        guard try symmetric.decryptAndHash(Data(message.dropFirst(32))).isEmpty else {
            throw NoiseError.invalidMessage
        }

        (sendCipher, receiveCipher) = symmetric.split()
        phase = .transport
    }

    func encryptTransport(_ plaintext: Data) throws -> Data {
        guard phase == .transport, var cipher = sendCipher else {
            throw NoiseError.invalidState
        }
        guard plaintext.count <= Self.maxPlaintextBytes else {
            throw NoiseError.messageTooLarge
        }
        let ciphertext = try cipher.encrypt(ad: Data(), plaintext: plaintext)
        sendCipher = cipher
        return ciphertext
    }

    func decryptTransport(_ ciphertext: Data) throws -> Data {
        guard phase == .transport, var cipher = receiveCipher else {
            throw NoiseError.invalidState
        }
        guard ciphertext.count <= Self.maxPlaintextBytes + 16 else {
            throw NoiseError.messageTooLarge
        }
        let plaintext = try cipher.decrypt(ad: Data(), ciphertext: ciphertext)
        receiveCipher = cipher
        return plaintext
    }
}

private struct NoiseSymmetricState {
    private(set) var chainingKey: Data
    private(set) var handshakeHash: Data
    private var cipher = NoiseCipherState(key: nil)

    init(protocolName: Data) {
        let initialHash: Data
        if protocolName.count <= 32 {
            initialHash = protocolName + Data(repeating: 0, count: 32 - protocolName.count)
        } else {
            initialHash = Data(SHA256.hash(data: protocolName))
        }
        chainingKey = initialHash
        handshakeHash = initialHash
    }

    mutating func mixHash(_ data: Data) {
        handshakeHash = Data(SHA256.hash(data: handshakeHash + data))
    }

    mutating func mixKey(_ inputKeyMaterial: Data) {
        let outputs = noiseHKDF(chainingKey: chainingKey, inputKeyMaterial: inputKeyMaterial)
        chainingKey = outputs.0
        cipher = NoiseCipherState(key: outputs.1)
    }

    mutating func mixKeyAndHash(_ inputKeyMaterial: Data) {
        let outputs = noiseHKDF3(
            chainingKey: chainingKey,
            inputKeyMaterial: inputKeyMaterial
        )
        chainingKey = outputs.0
        mixHash(outputs.1)
        cipher = NoiseCipherState(key: outputs.2)
    }

    mutating func encryptAndHash(_ plaintext: Data) throws -> Data {
        let ciphertext = try cipher.encrypt(ad: handshakeHash, plaintext: plaintext)
        mixHash(ciphertext)
        return ciphertext
    }

    mutating func decryptAndHash(_ ciphertext: Data) throws -> Data {
        let plaintext = try cipher.decrypt(ad: handshakeHash, ciphertext: ciphertext)
        mixHash(ciphertext)
        return plaintext
    }

    func split() -> (NoiseCipherState, NoiseCipherState) {
        let keys = noiseHKDF(chainingKey: chainingKey, inputKeyMaterial: Data())
        return (NoiseCipherState(key: keys.0), NoiseCipherState(key: keys.1))
    }
}

private struct NoiseCipherState {
    private let key: SymmetricKey?
    private var nonce: UInt64 = 0

    init(key: Data?) {
        self.key = key.map(SymmetricKey.init(data:))
    }

    mutating func encrypt(ad: Data, plaintext: Data) throws -> Data {
        guard let key else { return plaintext }
        guard nonce < UInt64.max else { throw NoiseError.nonceExhausted }
        let sealed = try ChaChaPoly.seal(
            plaintext,
            using: key,
            nonce: try ChaChaPoly.Nonce(data: noiseNonce(nonce)),
            authenticating: ad
        )
        nonce += 1
        return sealed.ciphertext + sealed.tag
    }

    mutating func decrypt(ad: Data, ciphertext: Data) throws -> Data {
        guard let key else { return ciphertext }
        guard nonce < UInt64.max, ciphertext.count >= 16 else {
            throw NoiseError.invalidMessage
        }
        let box = try ChaChaPoly.SealedBox(
            nonce: ChaChaPoly.Nonce(data: noiseNonce(nonce)),
            ciphertext: ciphertext.dropLast(16),
            tag: ciphertext.suffix(16)
        )
        let plaintext = try ChaChaPoly.open(box, using: key, authenticating: ad)
        nonce += 1
        return plaintext
    }
}

private func noiseDH(
    _ privateKey: Curve25519.KeyAgreement.PrivateKey,
    _ publicKey: Curve25519.KeyAgreement.PublicKey
) throws -> Data {
    let secret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
    let data = secret.withUnsafeBytes { Data($0) }
    guard !data.allSatisfy({ $0 == 0 }) else { throw NoiseError.invalidKey }
    return data
}

private func noiseHKDF(
    chainingKey: Data,
    inputKeyMaterial: Data
) -> (Data, Data) {
    let temporaryKey = noiseHMAC(key: chainingKey, data: inputKeyMaterial)
    let output1 = noiseHMAC(key: temporaryKey, data: Data([1]))
    let output2 = noiseHMAC(key: temporaryKey, data: output1 + Data([2]))
    return (output1, output2)
}

private func noiseHKDF3(
    chainingKey: Data,
    inputKeyMaterial: Data
) -> (Data, Data, Data) {
    let temporaryKey = noiseHMAC(key: chainingKey, data: inputKeyMaterial)
    let output1 = noiseHMAC(key: temporaryKey, data: Data([1]))
    let output2 = noiseHMAC(key: temporaryKey, data: output1 + Data([2]))
    let output3 = noiseHMAC(key: temporaryKey, data: output2 + Data([3]))
    return (output1, output2, output3)
}

private func noiseHMAC(key: Data, data: Data) -> Data {
    Data(HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: key)))
}

private func noiseNonce(_ value: UInt64) -> Data {
    var bytes = [UInt8](repeating: 0, count: 12)
    withUnsafeBytes(of: value.littleEndian) { rawBytes in
        bytes.replaceSubrange(4..<12, with: rawBytes)
    }
    return Data(bytes)
}
