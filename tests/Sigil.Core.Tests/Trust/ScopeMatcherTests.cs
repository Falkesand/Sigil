using Sigil.Trust;

namespace Sigil.Core.Tests.Trust;

public class ScopeMatcherTests
{
    [Fact]
    public void Null_scopes_matches_everything()
    {
        Assert.True(ScopeMatcher.Matches(null, "anything.tar.gz", "any-label", "ecdsa-p256"));
    }

    [Fact]
    public void Empty_scope_lists_match_everything()
    {
        var scopes = new TrustScopes();
        Assert.True(ScopeMatcher.Matches(scopes, "anything.tar.gz", "any-label", "ecdsa-p256"));
    }

    [Fact]
    public void Name_pattern_matches()
    {
        var scopes = new TrustScopes { NamePatterns = ["*.tar.gz", "*.zip"] };

        Assert.True(ScopeMatcher.Matches(scopes, "release.tar.gz", null, null));
        Assert.True(ScopeMatcher.Matches(scopes, "archive.zip", null, null));
        Assert.False(ScopeMatcher.Matches(scopes, "file.txt", null, null));
    }

    [Fact]
    public void Label_matches_exact()
    {
        var scopes = new TrustScopes { Labels = ["release", "ci-pipeline"] };

        Assert.True(ScopeMatcher.Matches(scopes, null, "release", null));
        Assert.True(ScopeMatcher.Matches(scopes, null, "ci-pipeline", null));
        Assert.False(ScopeMatcher.Matches(scopes, null, "dev", null));
    }

    [Fact]
    public void Algorithm_matches_exact()
    {
        var scopes = new TrustScopes { Algorithms = ["ecdsa-p256"] };

        Assert.True(ScopeMatcher.Matches(scopes, null, null, "ecdsa-p256"));
        Assert.False(ScopeMatcher.Matches(scopes, null, null, "rsa-pss-sha256"));
    }

    [Fact]
    public void All_scope_dimensions_must_match()
    {
        var scopes = new TrustScopes
        {
            NamePatterns = ["*.tar.gz"],
            Labels = ["release"],
            Algorithms = ["ecdsa-p256"]
        };

        Assert.True(ScopeMatcher.Matches(scopes, "file.tar.gz", "release", "ecdsa-p256"));
        Assert.False(ScopeMatcher.Matches(scopes, "file.zip", "release", "ecdsa-p256"));
        Assert.False(ScopeMatcher.Matches(scopes, "file.tar.gz", "dev", "ecdsa-p256"));
        Assert.False(ScopeMatcher.Matches(scopes, "file.tar.gz", "release", "rsa-pss-sha256"));
    }

    [Fact]
    public void Null_artifact_name_skips_name_check()
    {
        var scopes = new TrustScopes { NamePatterns = ["*.tar.gz"] };

        Assert.True(ScopeMatcher.Matches(scopes, null, null, null));
    }

    [Fact]
    public void Null_label_skips_label_check()
    {
        var scopes = new TrustScopes { Labels = ["release"] };

        Assert.True(ScopeMatcher.Matches(scopes, null, null, null));
    }

    [Fact]
    public void Null_algorithm_skips_algorithm_check()
    {
        var scopes = new TrustScopes { Algorithms = ["ecdsa-p256"] };

        Assert.True(ScopeMatcher.Matches(scopes, null, null, null));
    }

    [Fact]
    public void Intersect_both_null_returns_null()
    {
        Assert.Null(ScopeMatcher.Intersect(null, null));
    }

    [Fact]
    public void Intersect_one_null_returns_other()
    {
        var scopes = new TrustScopes { Labels = ["release"] };

        var result = ScopeMatcher.Intersect(scopes, null);

        Assert.NotNull(result);
        Assert.Equal(["release"], result.Labels);
    }

    [Fact]
    public void Intersect_combines_restrictions()
    {
        var a = new TrustScopes { NamePatterns = ["*.tar.gz"], Labels = ["release"] };
        var b = new TrustScopes { Labels = ["ci-pipeline"], Algorithms = ["ecdsa-p256"] };

        var result = ScopeMatcher.Intersect(a, b);

        Assert.NotNull(result);
        Assert.Equal(["*.tar.gz"], result!.NamePatterns);
        Assert.Equal(["release", "ci-pipeline"], result.Labels);
        Assert.Equal(["ecdsa-p256"], result.Algorithms);
    }

    [Fact]
    public void Intersect_merges_name_patterns()
    {
        var a = new TrustScopes { NamePatterns = ["*.tar.gz"] };
        var b = new TrustScopes { NamePatterns = ["*.zip"] };

        var result = ScopeMatcher.Intersect(a, b);

        Assert.NotNull(result);
        Assert.Equal(["*.tar.gz", "*.zip"], result!.NamePatterns);
    }
}
