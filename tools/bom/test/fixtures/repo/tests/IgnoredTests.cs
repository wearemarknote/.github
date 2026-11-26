using System.Security.Cryptography;

namespace Fixture.Tests;

/// Under tests/, which the scanner never reads: SHA1 and MD5 here must not appear.
public static class IgnoredTests
{
    public static byte[] Weak(byte[] bytes) => SHA1.HashData(MD5.HashData(bytes));
}
