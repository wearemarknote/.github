using System.Security.Cryptography;

namespace Fixture.Caching;

/// A hash that is a cache validator, not a security control: the manifest
/// declares it with securityRelevant false and files limited to this folder.
public static class ETags
{
    public static string Of(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes))[..16];
}
