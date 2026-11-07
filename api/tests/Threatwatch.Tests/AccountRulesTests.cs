using Threatwatch.Core.Identity;

namespace Threatwatch.Tests;

public class AccountRulesTests
{
    [Theory]
    [InlineData("dev@example.com", true)]
    [InlineData("dev@example.co.uk", true)]
    [InlineData("not-an-email", false)]
    [InlineData("a@b", false)]
    [InlineData("a@b.", false)]
    [InlineData("dev example@example.com", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void EmailMustLookLikeAnAddress(string? email, bool expected)
    {
        Assert.Equal(expected, AccountRules.IsValidEmail(email));
    }

    [Fact]
    public void EmailRejectsValuesLongerThan254Characters()
    {
        var email = "a@" + new string('b', 249) + ".co";
        Assert.Equal(254, email.Length);
        Assert.True(AccountRules.IsValidEmail(email));
        Assert.False(AccountRules.IsValidEmail("a" + email));
    }

    [Fact]
    public void DisplayNameFallsBackToTheEmailLocalPart()
    {
        Assert.Equal("dev", AccountRules.NormalizeDisplayName("  ", "dev@example.com"));
        Assert.Equal("Ada", AccountRules.NormalizeDisplayName(" Ada ", "dev@example.com"));
    }

    [Fact]
    public void DisplayNameIsCappedAt80Characters()
    {
        var name = AccountRules.NormalizeDisplayName(new string('x', 120), "dev@example.com");
        Assert.Equal(80, name.Length);
    }
}

public class RegistrationOptionsTests
{
    [Fact]
    public void NoInviteCodeAcceptsAnything()
    {
        var o = new Threatwatch.Core.Identity.RegistrationOptions();
        Assert.False(o.HasInviteCode);
        Assert.True(o.InviteMatches(null));
    }

    [Fact]
    public void InviteCodeMustMatchIgnoringSurroundingSpace()
    {
        var o = new Threatwatch.Core.Identity.RegistrationOptions { InviteCode = "s3cret" };
        Assert.True(o.InviteMatches(" s3cret "));
        Assert.False(o.InviteMatches("wrong"));
        Assert.False(o.InviteMatches(null));
    }
}
