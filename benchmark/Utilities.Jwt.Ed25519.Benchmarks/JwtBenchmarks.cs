using BenchmarkDotNet.Attributes;
using Org.BouncyCastle.Crypto.Parameters;
using Utilities.Jwt.Ed25519.Interfaces;
using Utilities.Jwt.Ed25519.Models;
using Utilities.Jwt.Ed25519.Services;

namespace Utilities.Jwt.Ed25519.Benchmarks;

/// <summary>
/// Measures token build and token validation.
/// </summary>
/// <remarks>
/// The "LoadKeyEachCall" benchmarks parse the PEM key in each call. The 8.x README results use this method.
/// The "PreloadedKey" benchmarks load the key once. The dependency injection registration of version 10.0 uses this method.
/// NOTE: BenchmarkDotNet does not accept a sealed benchmark class.
/// </remarks>
[MemoryDiagnoser]
public class JwtBenchmarks
{
	// NOTE: These keys are benchmark keys only. No system uses them.
	private const string PrivateKeyPem = """
		-----BEGIN PRIVATE KEY-----
		MC4CAQAwBQYDK2VwBCIEIBjirw/3PNIj5F6kfA100R6k2s9Wgb7yxYrVZbDfnOJf
		-----END PRIVATE KEY-----
		""";

	private const string PublicKeyPem = """
		-----BEGIN PUBLIC KEY-----
		MCowBQYDK2VwAyEAFYcbSrDaJytx/y7qxFZQpUGb+GORxSBWY2PrOo5fnIY=
		-----END PUBLIC KEY-----
		""";

	private readonly JwtSigner _signer = new();
	private Ed25519PrivateKeyParameters _privateKey = null!;
	private Ed25519PublicKeyParameters _publicKey = null!;
	private JwtValidator _validator = null!;
	private BenchmarkPayload _payload = null!;
	private string _token = null!;

	/// <summary>
	/// Loads the keys and builds the token that the validation benchmarks use.
	/// </summary>
	[GlobalSetup]
	public void Setup()
	{
		var now = DateTimeOffset.UtcNow;

		// Set exp in the future. The validation benchmarks must run all checks, not stop at the lifetime check.
		_payload = new BenchmarkPayload
		{
			Subject = "Subject",
			Issuer = "Issuer",
			Audience = "Audience",
			Expiration = now.AddDays(30).ToUnixTimeSeconds(),
			IssuedAt = now.ToUnixTimeSeconds(),
			NotBefore = now.ToUnixTimeSeconds(),
			JwtId = "26eb75d3-b86b-4954-be70-99e7d34f13cb",
			CustomClaim = "CustomClaimValue"
		};

		_privateKey = Ed25519KeyLoader.LoadPrivateKey(PrivateKeyPem);
		_publicKey = Ed25519KeyLoader.LoadPublicKey(PublicKeyPem);
		_validator = new JwtValidator(new FixedKeyResolver(new JwtVerificationKey(_publicKey)), null, null);
		_token = _signer.BuildToken(_payload, _privateKey);

		if (!_validator.TryValidateToken<BenchmarkPayload>(_token, _publicKey, out _))
			throw new InvalidOperationException("The benchmark token is not valid.");
	}

	/// <summary>
	/// Builds a token with a key that the setup loaded.
	/// </summary>
	[Benchmark]
	public string BuildToken_PreloadedKey() =>
		_signer.BuildToken(_payload, _privateKey);

	/// <summary>
	/// Validates a token with a key that the setup loaded.
	/// </summary>
	[Benchmark]
	public bool ValidateToken_PreloadedKey() =>
		_validator.TryValidateToken<BenchmarkPayload>(_token, _publicKey, out _);

	/// <summary>
	/// Loads the private key and builds a token.
	/// </summary>
	[Benchmark]
	public string BuildToken_LoadKeyEachCall() =>
		_signer.BuildToken(_payload, Ed25519KeyLoader.LoadPrivateKey(PrivateKeyPem));

	/// <summary>
	/// Loads the public key and validates a token.
	/// </summary>
	[Benchmark]
	public bool ValidateToken_LoadKeyEachCall() =>
		_validator.TryValidateToken<BenchmarkPayload>(_token, Ed25519KeyLoader.LoadPublicKey(PublicKeyPem), out _);

	/// <summary>
	/// Validates a token with the key from a resolver.
	/// </summary>
	[Benchmark]
	public bool ValidateTokenAsync_Resolver() =>
		_validator.ValidateTokenAsync<BenchmarkPayload>(_token, CancellationToken.None).AsTask().GetAwaiter().GetResult().IsValid;

	/// <summary>
	/// Gives one key that the setup loaded.
	/// </summary>
	/// <param name="key">The key to give.</param>
	private sealed class FixedKeyResolver(JwtVerificationKey key) : IJwtKeyResolver
	{
		private readonly JwtVerificationKey _key = key;

		/// <inheritdoc />
		public ValueTask<JwtVerificationKey?> ResolvePublicKeyAsync(JwtKeyResolutionContext context, CancellationToken cancellationToken) =>
			new(_key);
	}
}
