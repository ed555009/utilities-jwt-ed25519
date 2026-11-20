using System.Text;
using Utilities.Jwt.Ed25519.Models;

namespace Utilities.Jwt.Ed25519.Tests.Models;

/// <summary>
/// Tests for <see cref="TokenParts"/>.
/// The validator uses TokenParts to split and decode a token. The tests pin the decoded parts
/// and the false result for each malformed token.
/// </summary>
public class TokenPartsTests
{
	[Fact]
	public void TryParse_ValidToken_ReturnsTrueAndDecodedParts()
	{
		// Given
		var token = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.AQID";

		// When
		var result = TokenParts.TryParse(token, out var parts);

		// Then
		Assert.True(result);
		Assert.NotNull(parts);
		Assert.Equal("eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0", parts.SignedData);
		Assert.Equal("{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}", Encoding.UTF8.GetString(parts.Header));
		Assert.Equal("{\"sub\":\"test\"}", Encoding.UTF8.GetString(parts.Payload));
		Assert.Equal(new byte[] { 1, 2, 3 }, parts.Signature);
	}

	[Theory]
	[InlineData(null)]
	[InlineData("")]
	[InlineData("a.b")]
	[InlineData("a.b.c.d")]
	[InlineData("e30.e30.@@@@")]
	[InlineData("e30=.e30.AQID")]
	public void TryParse_MalformedToken_ReturnsFalseAndNull(string? token)
	{
		// Given

		// When
		var result = TokenParts.TryParse(token, out var parts);

		// Then
		Assert.False(result);
		Assert.Null(parts);
	}
}
