// Copyright (c) 2026 Marknote Limited. All rights reserved.
//
// Part of the shared bills-of-materials workflow (wearemarknote/.github).
// Marknote is a trade mark of Marknote Limited. Provided "as is", without
// warranty of any kind.

// The catalogue of cryptography the scanner recognises (2026-11-26): for
// each language, the API symbols that mean a cryptographic primitive is in
// use, and the CycloneDX 1.6 shape a detection takes when nobody declared
// it. A detector is a regular expression over source with the comments
// taken out; where the algorithm is named by a string (a JCA transformation,
// a WebCrypto algorithm name), the first capture group is the variant and
// the detection's key is "<id>:<variant>", so a manifest can match
// "jvm.cipher:AES/GCM/NoPadding" and leave "jvm.cipher:AES/CBC/PKCS5Padding"
// to be flagged. Presence is what a detector proves; parameters (key sizes,
// costs) are the manifest's word.

export const languages = {
  csharp: ['.cs'],
  swift: ['.swift'],
  kotlin: ['.kt', '.kts', '.java'],
  js: ['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx'],
};

const algorithm = (name, primitive, extra = {}) => ({ name, assetType: 'algorithm', algorithm: { primitive, ...extra } });
const other = (name) => ({ name, assetType: 'algorithm', algorithm: { primitive: 'other' } });

/** @type {Array<{id: string, language: keyof typeof languages, pattern: RegExp, template: object, hint: string}>} */
export const detectors = [
  // ---- C# / .NET ---------------------------------------------------------
  { id: 'dotnet.aesgcm', language: 'csharp', pattern: /\bAesGcm\b/g, template: algorithm('AES-GCM', 'ae', { mode: 'gcm' }), hint: 'System.Security.Cryptography.AesGcm' },
  { id: 'dotnet.aesccm', language: 'csharp', pattern: /\bAesCcm\b/g, template: algorithm('AES-CCM', 'ae', { mode: 'ccm' }), hint: 'System.Security.Cryptography.AesCcm' },
  { id: 'dotnet.aes', language: 'csharp', pattern: /\bAes\.Create\(|\bAes(?:Managed|Cng|CryptoServiceProvider)\b/g, template: algorithm('AES', 'block-cipher'), hint: 'Aes.Create() and the older AES classes (a mode is set on the instance)' },
  { id: 'dotnet.chacha20poly1305', language: 'csharp', pattern: /\bChaCha20Poly1305\b/g, template: algorithm('ChaCha20-Poly1305', 'ae'), hint: 'System.Security.Cryptography.ChaCha20Poly1305' },
  { id: 'dotnet.sha256', language: 'csharp', pattern: /(?<![A-Za-z])SHA256(?:Managed|Cng|CryptoServiceProvider)?\b/g, template: algorithm('SHA-256', 'hash'), hint: 'SHA256.HashData, SHA256.Create' },
  { id: 'dotnet.sha384', language: 'csharp', pattern: /(?<![A-Za-z])SHA384(?:Managed|Cng|CryptoServiceProvider)?\b/g, template: algorithm('SHA-384', 'hash'), hint: 'SHA384' },
  { id: 'dotnet.sha512', language: 'csharp', pattern: /(?<![A-Za-z])SHA512(?:Managed|Cng|CryptoServiceProvider)?\b/g, template: algorithm('SHA-512', 'hash'), hint: 'SHA512' },
  { id: 'dotnet.sha1', language: 'csharp', pattern: /(?<![A-Za-z])SHA1(?:Managed|Cng|CryptoServiceProvider)?\b(?![0-9])/g, template: algorithm('SHA-1', 'hash'), hint: 'SHA1 (weak: only for interoperability, never for security)' },
  { id: 'dotnet.md5', language: 'csharp', pattern: /(?<![A-Za-z])MD5(?:Cng|CryptoServiceProvider)?\b/g, template: algorithm('MD5', 'hash'), hint: 'MD5 (broken: never for security)' },
  { id: 'dotnet.hmacsha256', language: 'csharp', pattern: /\bHMACSHA256\b/g, template: algorithm('HMAC-SHA256', 'mac'), hint: 'HMACSHA256' },
  { id: 'dotnet.hmacsha384', language: 'csharp', pattern: /\bHMACSHA384\b/g, template: algorithm('HMAC-SHA384', 'mac'), hint: 'HMACSHA384' },
  { id: 'dotnet.hmacsha512', language: 'csharp', pattern: /\bHMACSHA512\b/g, template: algorithm('HMAC-SHA512', 'mac'), hint: 'HMACSHA512' },
  { id: 'dotnet.hmacsha1', language: 'csharp', pattern: /\bHMACSHA1\b/g, template: algorithm('HMAC-SHA1', 'mac'), hint: 'HMACSHA1' },
  { id: 'dotnet.hkdf', language: 'csharp', pattern: /\bHKDF\b/g, template: algorithm('HKDF', 'kdf'), hint: 'System.Security.Cryptography.HKDF' },
  { id: 'dotnet.pbkdf2', language: 'csharp', pattern: /\bRfc2898DeriveBytes\b|\bPbkdf2\b/g, template: algorithm('PBKDF2', 'kdf'), hint: 'Rfc2898DeriveBytes, Rfc2898DeriveBytes.Pbkdf2' },
  { id: 'dotnet.argon2', language: 'csharp', pattern: /\bArgon2(id|i|d)?\b/g, template: algorithm('Argon2', 'kdf'), hint: 'Konscious.Security.Cryptography.Argon2*, NSec Argon2id, Isopoh' },
  { id: 'dotnet.scrypt', language: 'csharp', pattern: /\bScrypt\b/gi, template: algorithm('scrypt', 'kdf'), hint: 'scrypt' },
  { id: 'dotnet.rsa', language: 'csharp', pattern: /\bRSA(?:Cng|CryptoServiceProvider|OpenSsl)?\b|\bRSAEncryptionPadding\b|\bRSASignaturePadding\b/g, template: algorithm('RSA', 'pke'), hint: 'System.Security.Cryptography.RSA (encryption or signatures: the manifest says which)' },
  { id: 'dotnet.ecdh', language: 'csharp', pattern: /\bECDiffieHellman(?:Cng|OpenSsl|PublicKey)?\b/g, template: algorithm('ECDH', 'key-agree'), hint: 'ECDiffieHellman' },
  { id: 'dotnet.ecdsa', language: 'csharp', pattern: /\bECDsa(?:Cng|OpenSsl)?\b/g, template: algorithm('ECDSA', 'signature'), hint: 'ECDsa' },
  { id: 'dotnet.x25519', language: 'csharp', pattern: /\bX25519\b/g, template: algorithm('X25519', 'key-agree', { curve: 'X25519' }), hint: 'X25519 (NSec or a comment: the scanner ignores comments)' },
  { id: 'dotnet.ed25519', language: 'csharp', pattern: /\bEd25519\b/g, template: algorithm('Ed25519', 'signature', { curve: 'Ed25519' }), hint: 'Ed25519' },
  { id: 'dotnet.rng', language: 'csharp', pattern: /\bRandomNumberGenerator\b/g, template: algorithm('CSPRNG', 'drbg'), hint: 'RandomNumberGenerator' },
  { id: 'dotnet.dataprotection', language: 'csharp', pattern: /\bIDataProtector\b|\bIDataProtectionProvider\b|\bAddDataProtection\s*\(|\bProtectKeysWith\w*\s*\(|\bITimeLimitedDataProtector\b/g, template: other('ASP.NET Core Data Protection'), hint: 'the Data Protection stack (AES-256-CBC + HMAC-SHA256 keyring)' },
  { id: 'dotnet.dpapi', language: 'csharp', pattern: /\bProtectedData\.(?:Protect|Unprotect)\b|\bDataProtectionScope\b/g, template: other('Windows DPAPI'), hint: 'System.Security.Cryptography.ProtectedData' },
  { id: 'dotnet.passwordhasher', language: 'csharp', pattern: /\bI?PasswordHasher(?:Options)?\s*</g, template: algorithm('PBKDF2-HMAC (ASP.NET Identity)', 'kdf'), hint: 'ASP.NET Identity PasswordHasher<TUser> (PBKDF2-HMAC-SHA512 in V3)' },
  { id: 'dotnet.nsec', language: 'csharp', pattern: /\bNSec\.Cryptography\b|\bPasswordBasedKeyDerivationAlgorithm\b|\bAeadAlgorithm\b|\bKeyAgreementAlgorithm\b|\bSignatureAlgorithm\.Ed25519\b/g, template: other('NSec (libsodium)'), hint: 'NSec.Cryptography types' },
  { id: 'dotnet.passkeys', language: 'csharp', pattern: /\bPasskey(?:UserEntity|CreationOptions|RequestOptions|Data|Options)\b|\bMakePasskey(?:Creation|Request)OptionsAsync\b|\bPerformPasskeyAttestationAsync\b|\bPerformPasskeyAssertionAsync\b|\bWebAuthn\b|\bFido2\b/g, template: algorithm('WebAuthn passkeys', 'signature'), hint: 'ASP.NET Core Identity passkeys, FIDO2/WebAuthn' },
  { id: 'dotnet.x509', language: 'csharp', pattern: /\bX509Certificate2\b|\bX509Chain\b|\bCertificateRequest\b/g, template: { name: 'X.509 certificates', assetType: 'certificate' }, hint: 'X509Certificate2 and chains' },
  { id: 'dotnet.tls', language: 'csharp', pattern: /\bSslProtocols\.Tls1[123]\b|\bSslStream\b|\bServerCertificateCustomValidationCallback\b|\bUseHsts\s*\(/g, template: { name: 'TLS', assetType: 'protocol', protocol: { type: 'tls' } }, hint: 'TLS settings, HSTS, custom certificate validation' },
  { id: 'dotnet.jwt', language: 'csharp', pattern: /\bJwtSecurityToken(?:Handler)?\b|\bJsonWebToken(?:Handler)?\b|\bSigningCredentials\b|\bRsaSecurityKey\b|\bSymmetricSecurityKey\b/g, template: algorithm('JWT signing', 'signature'), hint: 'JWT signing credentials' },

  // ---- Swift (CryptoKit, Security, CommonCrypto, libsodium) ---------------
  { id: 'swift.aesgcm', language: 'swift', pattern: /\bAES\.GCM\b/g, template: algorithm('AES-GCM', 'ae', { mode: 'gcm' }), hint: 'CryptoKit AES.GCM' },
  { id: 'swift.chachapoly', language: 'swift', pattern: /\bChaChaPoly\b/g, template: algorithm('ChaCha20-Poly1305', 'ae'), hint: 'CryptoKit ChaChaPoly' },
  { id: 'swift.sha256', language: 'swift', pattern: /(?<![A-Za-z])SHA256\b/g, template: algorithm('SHA-256', 'hash'), hint: 'CryptoKit SHA256' },
  { id: 'swift.sha384', language: 'swift', pattern: /(?<![A-Za-z])SHA384\b/g, template: algorithm('SHA-384', 'hash'), hint: 'CryptoKit SHA384' },
  { id: 'swift.sha512', language: 'swift', pattern: /(?<![A-Za-z])SHA512\b/g, template: algorithm('SHA-512', 'hash'), hint: 'CryptoKit SHA512' },
  { id: 'swift.insecure', language: 'swift', pattern: /\bInsecure\.(SHA1|MD5)\b/g, template: algorithm('Insecure hash', 'hash'), hint: 'CryptoKit Insecure.SHA1 / Insecure.MD5' },
  { id: 'swift.hmac', language: 'swift', pattern: /\bHMAC<\s*(SHA256|SHA384|SHA512)\s*>/g, template: algorithm('HMAC', 'mac'), hint: 'CryptoKit HMAC<SHA256>' },
  { id: 'swift.hkdf', language: 'swift', pattern: /\bHKDF<\s*(SHA256|SHA384|SHA512)\s*>/g, template: algorithm('HKDF', 'kdf'), hint: 'CryptoKit HKDF<SHA256>' },
  { id: 'swift.p256-keyagreement', language: 'swift', pattern: /\bP256\.KeyAgreement\b/g, template: algorithm('ECDH P-256', 'key-agree', { curve: 'P-256' }), hint: 'CryptoKit P256.KeyAgreement' },
  { id: 'swift.p256-signing', language: 'swift', pattern: /\bP256\.Signing\b/g, template: algorithm('ECDSA P-256', 'signature', { curve: 'P-256' }), hint: 'CryptoKit P256.Signing' },
  { id: 'swift.p384', language: 'swift', pattern: /\bP384\.(KeyAgreement|Signing)\b/g, template: algorithm('P-384', 'key-agree', { curve: 'P-384' }), hint: 'CryptoKit P384' },
  { id: 'swift.curve25519', language: 'swift', pattern: /\bCurve25519\.(KeyAgreement|Signing)\b/g, template: algorithm('Curve25519', 'key-agree', { curve: 'Curve25519' }), hint: 'CryptoKit Curve25519 (X25519 key agreement or Ed25519 signing)' },
  { id: 'swift.symmetrickey', language: 'swift', pattern: /\bSymmetricKey\s*\(\s*size:/g, template: other('Symmetric key generation'), hint: 'CryptoKit SymmetricKey(size:)' },
  { id: 'swift.secrandom', language: 'swift', pattern: /\bSecRandomCopyBytes\b|\bSystemRandomNumberGenerator\b/g, template: algorithm('CSPRNG', 'drbg'), hint: 'SecRandomCopyBytes, SystemRandomNumberGenerator' },
  { id: 'swift.commoncrypto', language: 'swift', pattern: /\bCC(Crypt|Hmac|KeyDerivationPBKDF|_SHA256|_SHA1|_MD5|CryptorCreate)\b/g, template: other('CommonCrypto'), hint: 'CommonCrypto calls' },
  { id: 'swift.argon2', language: 'swift', pattern: /\bargon2(id|i|d)?_hash(?:_raw|_encoded)?\b|\bArgon2(id|i|d)?\b/g, template: algorithm('Argon2', 'kdf'), hint: 'argon2id_hash_raw and friends, or an Argon2 type' },
  { id: 'swift.libsodium', language: 'swift', pattern: /\bcrypto_(pwhash|aead|secretbox|box|sign|generichash|kdf|auth)\w*/g, template: other('libsodium'), hint: 'libsodium calls' },
  { id: 'swift.keychain', language: 'swift', pattern: /\bSecItem(?:Add|CopyMatching|Update|Delete)\b|\bkSecClass\w*\b|\bSecKeyCreate\w*\b/g, template: other('Keychain / Security framework'), hint: 'SecItem*, SecKey*' },
  { id: 'swift.localauth', language: 'swift', pattern: /\bLAContext\b|\bLAPolicy\b/g, template: other('LocalAuthentication'), hint: 'LocalAuthentication (biometrics)' },

  // ---- Kotlin / Java (JCA, Android Keystore, libsodium) -------------------
  { id: 'jvm.cipher', language: 'kotlin', pattern: /\bCipher\.getInstance\(\s*"([^"]+)"/g, template: algorithm('Cipher', 'block-cipher'), hint: 'javax.crypto.Cipher.getInstance("<transformation>")' },
  { id: 'jvm.messagedigest', language: 'kotlin', pattern: /\bMessageDigest\.getInstance\(\s*"([^"]+)"/g, template: algorithm('Message digest', 'hash'), hint: 'MessageDigest.getInstance("<algorithm>")' },
  { id: 'jvm.mac', language: 'kotlin', pattern: /\bMac\.getInstance\(\s*"([^"]+)"/g, template: algorithm('MAC', 'mac'), hint: 'javax.crypto.Mac.getInstance("<algorithm>")' },
  { id: 'jvm.secretkeyfactory', language: 'kotlin', pattern: /\bSecretKeyFactory\.getInstance\(\s*"([^"]+)"/g, template: algorithm('Key derivation', 'kdf'), hint: 'SecretKeyFactory.getInstance("<algorithm>")' },
  { id: 'jvm.keyagreement', language: 'kotlin', pattern: /\bKeyAgreement\.getInstance\(\s*"([^"]+)"/g, template: algorithm('Key agreement', 'key-agree'), hint: 'KeyAgreement.getInstance("<algorithm>")' },
  { id: 'jvm.keypairgenerator', language: 'kotlin', pattern: /\bKeyPairGenerator\.getInstance\(\s*"([^"]+)"/g, template: algorithm('Key pair generation', 'other'), hint: 'KeyPairGenerator.getInstance("<algorithm>")' },
  { id: 'jvm.keygenerator', language: 'kotlin', pattern: /\bKeyGenerator\.getInstance\(\s*"([^"]+)"/g, template: algorithm('Key generation', 'other'), hint: 'KeyGenerator.getInstance("<algorithm>")' },
  { id: 'jvm.signature', language: 'kotlin', pattern: /\bSignature\.getInstance\(\s*"([^"]+)"/g, template: algorithm('Signature', 'signature'), hint: 'java.security.Signature.getInstance("<algorithm>")' },
  { id: 'jvm.ecparam', language: 'kotlin', pattern: /\bECGenParameterSpec\(\s*"([^"]+)"/g, template: algorithm('EC curve', 'key-agree'), hint: 'ECGenParameterSpec("<curve>")' },
  { id: 'jvm.securerandom', language: 'kotlin', pattern: /\bSecureRandom\b/g, template: algorithm('CSPRNG', 'drbg'), hint: 'java.security.SecureRandom' },
  { id: 'jvm.keystore', language: 'kotlin', pattern: /"AndroidKeyStore"|\bKeyGenParameterSpec\b|\bKeyStore\.getInstance\(/g, template: other('Android Keystore'), hint: 'AndroidKeyStore, KeyGenParameterSpec' },
  { id: 'jvm.biometric', language: 'kotlin', pattern: /\bBiometricPrompt\b|\bsetUserAuthenticationRequired\s*\(/g, template: other('Biometric / user-authentication binding'), hint: 'BiometricPrompt, user-authentication-bound keys' },
  { id: 'jvm.argon2', language: 'kotlin', pattern: /\bArgon2(?:Kt|Mode|Version|Exception)?\b|\bargon2kt\b/g, template: algorithm('Argon2', 'kdf'), hint: 'argon2kt or another Argon2 binding' },
  { id: 'jvm.libsodium', language: 'kotlin', pattern: /\bLazySodium\w*\b|\bcrypto_(?:pwhash|aead|secretbox|box|sign)\w*/g, template: other('libsodium'), hint: 'lazysodium or libsodium calls' },
  { id: 'jvm.tink', language: 'kotlin', pattern: /\bcom\.google\.crypto\.tink\b|\bAeadConfig\b|\bKeysetHandle\b/g, template: other('Tink'), hint: 'Google Tink' },
  { id: 'jvm.encryptedprefs', language: 'kotlin', pattern: /\bEncryptedSharedPreferences\b|\bEncryptedFile\b|\bMasterKey\b/g, template: other('androidx.security.crypto'), hint: 'EncryptedSharedPreferences / MasterKey' },
  { id: 'jvm.pinning', language: 'kotlin', pattern: /\bCertificatePinner\b|\bnetwork_security_config\b|\bTrustManager\b/g, template: { name: 'TLS trust', assetType: 'protocol', protocol: { type: 'tls' } }, hint: 'certificate pinning or custom trust' },

  // ---- JavaScript / TypeScript (WebCrypto, Node) --------------------------
  { id: 'js.subtle', language: 'js', pattern: /\bcrypto\.subtle\.(encrypt|decrypt|sign|verify|digest|deriveKey|deriveBits|importKey|exportKey|generateKey|wrapKey|unwrapKey)\s*\(/g, template: other('WebCrypto'), hint: 'crypto.subtle.<method>(' },
  { id: 'js.algorithm', language: 'js', pattern: /["'](AES-GCM|AES-CBC|AES-CTR|AES-KW|HKDF|PBKDF2|HMAC|ECDH|ECDSA|RSA-OAEP|RSASSA-PKCS1-v1_5|RSA-PSS|Ed25519|X25519|SHA-1|SHA-256|SHA-384|SHA-512)["']/g, template: other('WebCrypto algorithm name'), hint: 'an algorithm name string such as "AES-GCM" or "SHA-256"' },
  { id: 'js.getrandomvalues', language: 'js', pattern: /\bcrypto\.getRandomValues\s*\(|\bcrypto\.randomUUID\s*\(/g, template: algorithm('CSPRNG', 'drbg'), hint: 'crypto.getRandomValues, crypto.randomUUID' },
  { id: 'js.nodecrypto', language: 'js', pattern: /\bcreateHash\(\s*["']([^"']+)["']|\bcreateHmac\(\s*["']([^"']+)["']|\bcreateCipheriv\(\s*["']([^"']+)["']|\bpbkdf2(?:Sync)?\s*\(|\bscrypt(?:Sync)?\s*\(|\bhkdf(?:Sync)?\s*\(|\brandomBytes\s*\(/g, template: other('Node crypto'), hint: 'node:crypto calls' },
  { id: 'js.libsodium', language: 'js', pattern: /\blibsodium(?:-wrappers)?\b|\bsodium\.crypto_\w+/g, template: other('libsodium.js'), hint: 'libsodium-wrappers' },
];

/** The detection key a manifest names: the id, or id:variant when the regex captured one. */
export function keyOf(detectorId, variant) {
  return variant ? `${detectorId}:${variant}` : detectorId;
}

export const detectorIds = new Set(detectors.map(d => d.id));

export function detectorById(id) {
  return detectors.find(d => d.id === id);
}
