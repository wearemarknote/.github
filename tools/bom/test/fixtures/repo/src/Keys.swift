import CryptoKit
import Foundation

// SHA512 in a comment must not count.
enum Keys {
    static func agree(mine: P256.KeyAgreement.PrivateKey, theirs: P256.KeyAgreement.PublicKey) throws -> SymmetricKey {
        let shared = try mine.sharedSecretFromKeyAgreement(with: theirs)
        return shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data(), sharedInfo: Data("marknote-member-wrap-v1".utf8), outputByteCount: 32)
    }

    static func tag(key: SymmetricKey, message: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: message, using: key))
    }

    static func seal(key: SymmetricKey, plaintext: Data) throws -> Data {
        try AES.GCM.seal(plaintext, using: key).combined!
    }

    static func subkey(key: SymmetricKey, info: String) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: key, info: Data(info.utf8), outputByteCount: 32)
    }
}
