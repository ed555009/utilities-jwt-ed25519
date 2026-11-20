using Utilities.Jwt.Ed25519.Services;

namespace Utilities.Jwt.Ed25519.Tests.Services;

/// <summary>
/// Tests for <see cref="Base64Url"/>.
/// The decoder rejects padding and characters outside the Base64 URL alphabet.
/// The validator depends on this rule to keep the signed data ASCII.
/// </summary>
public class Base64UrlTests
{
	[Theory]
	[InlineData(new byte[] { }, "")]
	[InlineData(new byte[] { 0xfb }, "-w")]
	[InlineData(new byte[] { 0xfb, 0xff }, "-_8")]
	[InlineData(new byte[] { 0xfb, 0xff, 0xbf }, "-_-_")]
	public void Encode_Bytes_ReturnsBase64UrlWithoutPadding(byte[] data, string expected)
	{
		// Given

		// When
		var result = Base64Url.Encode(data);

		// Then
		Assert.Equal(expected, result);
	}

	[Theory]
	[InlineData("", new byte[] { })]
	[InlineData("-w", new byte[] { 0xfb })]
	[InlineData("-_8", new byte[] { 0xfb, 0xff })]
	[InlineData("-_-_", new byte[] { 0xfb, 0xff, 0xbf })]
	public void TryDecode_Base64UrlWithoutPadding_ReturnsTrueAndBytes(string data, byte[] expected)
	{
		// Given

		// When
		var result = Base64Url.TryDecode(data, out var bytes);

		// Then
		Assert.True(result);
		Assert.Equal(expected, bytes);
	}

	[Theory]
	[InlineData("-w==")]
	[InlineData("+w")]
	[InlineData("/w")]
	[InlineData("-w ")]
	[InlineData("@@@@")]
	[InlineData("[w")]
	[InlineData("`w")]
	[InlineData(":w")]
	[InlineData("{w")]
	[InlineData("A")]
	public void TryDecode_InvalidBase64Url_ReturnsFalseAndEmptyBytes(string data)
	{
		// Given

		// When
		var result = Base64Url.TryDecode(data, out var bytes);

		// Then
		Assert.False(result);
		Assert.Empty(bytes);
	}
}
