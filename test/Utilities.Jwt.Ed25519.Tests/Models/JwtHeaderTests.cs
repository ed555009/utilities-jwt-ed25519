using Utilities.Jwt.Ed25519.Models;

namespace Utilities.Jwt.Ed25519.Tests.Models;

/// <summary>
/// Tests for <see cref="JwtHeader"/>.
/// A header without kid must stay the same as in version 8.x. Otherwise the token format changes.
/// </summary>
public class JwtHeaderTests
{
	[Fact]
	public void Export_NoKeyId_ReturnsHeaderOfVersion8()
	{
		// Given
		var header = new JwtHeader();

		// When
		var json = header.Export();

		// Then
		Assert.Equal("{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}", json);
	}

	[Fact]
	public void Export_KeyId_AddsKidAfterAlgAndTyp()
	{
		// Given
		var header = new JwtHeader("member-1.v2");

		// When
		var json = header.Export();

		// Then
		Assert.Equal("{\"alg\":\"EdDSA\",\"typ\":\"JWT\",\"kid\":\"member-1.v2\"}", json);
	}
}
