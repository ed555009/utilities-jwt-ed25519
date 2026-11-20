using Utilities.Jwt.Ed25519.Services;

namespace Utilities.Jwt.Ed25519.Tests.Services;

/// <summary>
/// Tests for <see cref="KeyIdFormat"/>.
/// The format rule is a security control. A resolver can use kid as a database key or a file name,
/// so the rule must reject path separators, quotes, whitespace, and long values.
/// </summary>
public class KeyIdFormatTests
{
	[Theory]
	[InlineData("a")]
	[InlineData("member-1")]
	[InlineData("member_1.v2")]
	[InlineData("tenant:42")]
	[InlineData("AZaz09._:-")]
	public void IsValid_AllowedCharacters_ReturnsTrue(string keyId)
	{
		// Given

		// When
		var result = KeyIdFormat.IsValid(keyId);

		// Then
		Assert.True(result);
	}

	[Fact]
	public void IsValid_MaxLength_ReturnsTrue()
	{
		// Given
		var keyId = new string('a', KeyIdFormat.MaxLength);

		// When
		var result = KeyIdFormat.IsValid(keyId);

		// Then
		Assert.True(result);
	}

	[Fact]
	public void IsValid_LongerThanMaxLength_ReturnsFalse()
	{
		// Given
		var keyId = new string('a', KeyIdFormat.MaxLength + 1);

		// When
		var result = KeyIdFormat.IsValid(keyId);

		// Then
		Assert.False(result);
	}

	[Theory]
	[InlineData(null)]
	[InlineData("")]
	[InlineData("../keys/admin")]
	[InlineData("a/b")]
	[InlineData("a\\b")]
	[InlineData("a b")]
	[InlineData("a'b")]
	[InlineData("a\"b")]
	[InlineData("a;b")]
	[InlineData("a\nb")]
	[InlineData("ａ")]
	[InlineData("@")]
	[InlineData("[")]
	[InlineData("`")]
	[InlineData("{")]
	public void IsValid_ForbiddenValue_ReturnsFalse(string? keyId)
	{
		// Given

		// When
		var result = KeyIdFormat.IsValid(keyId);

		// Then
		Assert.False(result);
	}
}
