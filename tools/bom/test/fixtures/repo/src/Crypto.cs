// A fixture: the shapes the scanner must and must not see.
// The sharing curve is P-256, not X25519, whatever this comment says.
using System.Security.Cryptography;

namespace Fixture;

/* Block comment naming SHA1 and MD5, which must not count. */
public static class Crypto
{
    public static byte[] Seal(byte[] key, byte[] plaintext)
    {
        using var aes = new AesGcm(key, 16);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        return nonce;
    }

    public static byte[] Derive(byte[] vaultKey, string info) =>
        HKDF.DeriveKey(HashAlgorithmName.SHA256, vaultKey, 32, info: System.Text.Encoding.UTF8.GetBytes(info));

    // A hand-written helper the manifest matches by an inline pattern.
    public static byte[] DigestOf(byte[] bytes) => SHA256.HashData(bytes);

    public const string Note = "the string AES-GCM in C# is not the JavaScript detector's business";
}
