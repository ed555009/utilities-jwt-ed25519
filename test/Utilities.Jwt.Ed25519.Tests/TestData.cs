using System.Text;
using Org.BouncyCastle.Crypto.Signers;
using Utilities.Jwt.Ed25519.Services;

namespace Utilities.Jwt.Ed25519.Tests;

/// <summary>
/// Keys, tokens, and helpers that more than one test class uses.
/// </summary>
internal static class TestData
{
	// NOTE: These keys are test keys only. No system uses them.
	public const string PrivateKeyPem = """
		-----BEGIN PRIVATE KEY-----
		MC4CAQAwBQYDK2VwBCIEIBjirw/3PNIj5F6kfA100R6k2s9Wgb7yxYrVZbDfnOJf
		-----END PRIVATE KEY-----
		""";

	public const string PublicKeyPem = """
		-----BEGIN PUBLIC KEY-----
		MCowBQYDK2VwAyEAFYcbSrDaJytx/y7qxFZQpUGb+GORxSBWY2PrOo5fnIY=
		-----END PUBLIC KEY-----
		""";

	// The token has exp 1736152313 (2025-01-06 08:31:53Z). Version 8.0.973 built the same token.
	public const string FixedToken = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJjdXN0b21fY2xhaW0iOiJDdXN0b21DbGFpbVZhbHVlIiwiaXNzIjoidGVzdCIsInN1YiI6InRlc3QiLCJhdWQiOiJ0ZXN0IiwiZXhwIjoxNzM2MTUyMzEzLCJuYmYiOjE3MzYxNTIyNTMsImlhdCI6MTczNjE1MjI1MywianRpIjoiMjZlYjc1ZDMtYjg2Yi00OTU0LWJlNzAtOTllN2QzNGYxM2NiIn0.9xvehbqez-cJWiC8xnYsiI-vxh2rSru1JbNdp3nZYruTJhTp8EvSEQCcnLHEIhLfgp3x5wKQcsAarTxyGtuGCg";

	/// <summary>
	/// Creates the payload of <see cref="FixedToken"/>.
	/// </summary>
	public static CustomPayload CreateFixedPayload() => new()
	{
		Subject = "test",
		Issuer = "test",
		Audience = "test",
		Expiration = 1736152313,
		IssuedAt = 1736152253,
		NotBefore = 1736152253,
		JwtId = "26eb75d3-b86b-4954-be70-99e7d34f13cb",
		CustomClaim = "CustomClaimValue"
	};

	/// <summary>
	/// Creates a payload with the custom claim and the given lifetime claims.
	/// </summary>
	public static CustomPayload CreatePayload(long? expiration, long? notBefore) => new()
	{
		Subject = "test",
		Issuer = "test",
		Audience = "test",
		Expiration = expiration,
		NotBefore = notBefore,
		CustomClaim = "CustomClaimValue"
	};

	/// <summary>
	/// Signs raw header and payload JSON with the test private key.
	/// The tests use this method to build tokens that <see cref="JwtSigner"/> cannot build.
	/// </summary>
	public static string Sign(string header, string payload)
	{
		var data = $"{Base64UrlEncode(header)}.{Base64UrlEncode(payload)}";
		var bytes = Encoding.ASCII.GetBytes(data);
		var signer = new Ed25519Signer();
		signer.Init(true, Ed25519KeyLoader.LoadPrivateKey(PrivateKeyPem));
		signer.BlockUpdate(bytes, 0, bytes.Length);

		return $"{data}.{Base64UrlEncode(signer.GenerateSignature())}";
	}

	/// <summary>
	/// Encodes a UTF-8 string to Base64 URL without padding.
	/// </summary>
	public static string Base64UrlEncode(string data) =>
		Base64UrlEncode(Encoding.UTF8.GetBytes(data));

	/// <summary>
	/// Encodes bytes to Base64 URL without padding.
	/// </summary>
	/// <remarks>
	/// The tests do not use <see cref="Base64Url"/> here. A defect in <see cref="Base64Url"/> must not hide in the test data.
	/// </remarks>
	public static string Base64UrlEncode(byte[] data) =>
		Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
