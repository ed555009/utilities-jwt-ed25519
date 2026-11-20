using Utilities.Jwt.Ed25519.Models;

namespace Utilities.Jwt.Ed25519.Tests.Models;

/// <summary>
/// Tests for <see cref="TokenParts"/>.
/// JwtService no longer uses TokenParts, but TokenParts stays public API. The tests pin its decode behavior.
/// </summary>
public class TokenPartsTests
{
	[Fact]
	public void DecodedProperties_EncodedParts_ReturnDecodedValues()
	{
		// Given
		var parts = new TokenParts
		{
			Header = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9",
			Payload = "eyJzdWIiOiJ0ZXN0In0",
			Signature = "AQID"
		};

		// When
		var header = parts.DecodedHeader;
		var payload = parts.DecodedPayload;
		var signature = parts.DecodedSignature;

		// Then
		Assert.Equal("{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}", header);
		Assert.Equal("{\"sub\":\"test\"}", payload);
		Assert.Equal(new byte[] { 1, 2, 3 }, signature);
	}

	[Fact]
	public void DecodedProperties_NullParts_ReturnEmptyValues()
	{
		// Given
		var parts = new TokenParts();

		// When
		var header = parts.DecodedHeader;
		var payload = parts.DecodedPayload;
		var signature = parts.DecodedSignature;

		// Then
		Assert.Equal("{}", header);
		Assert.Equal("{}", payload);
		Assert.Empty(signature);
	}
}
