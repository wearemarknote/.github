using System.Security.Cryptography;

namespace Fixture.Generated;

/// Under a folder the manifest's scan.exclude names: ECDsa here must not appear.
public static class Excluded
{
    public static ECDsa Key() => ECDsa.Create();
}
