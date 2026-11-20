using BenchmarkDotNet.Attributes;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
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
	private readonly JwtSigner _signer = new();
	private string _privateKeyPem = null!;
	private string _publicKeyPem = null!;
	private Ed25519PrivateKeyParameters _privateKey = null!;
	private Ed25519PublicKeyParameters _publicKey = null!;
	private JwtValidator _validator = null!;
	private BenchmarkPayload _payload = null!;
	private string _token = null!;

	/// <summary>
	/// Generates the keys and builds the token that the validation benchmarks use.
	/// </summary>
	/// <remarks>
	/// The setup generates a new key pair in each run. Do not put a private key in the source code.
	/// </remarks>
	[GlobalSetup]
	public void Setup()
	{
		var generator = new Ed25519KeyPairGenerator();
		generator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
		var keyPair = generator.GenerateKeyPair();

		// The LoadKeyEachCall benchmarks parse PEM text. The 8.x README results use this method.
		_privateKeyPem = ToPem(PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private));
		_publicKeyPem = ToPem(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public));

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

		_privateKey = Ed25519KeyLoader.LoadPrivateKey(_privateKeyPem);
		_publicKey = Ed25519KeyLoader.LoadPublicKey(_publicKeyPem);
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
		_signer.BuildToken(_payload, Ed25519KeyLoader.LoadPrivateKey(_privateKeyPem));

	/// <summary>
	/// Loads the public key and validates a token.
	/// </summary>
	[Benchmark]
	public bool ValidateToken_LoadKeyEachCall() =>
		_validator.TryValidateToken<BenchmarkPayload>(_token, Ed25519KeyLoader.LoadPublicKey(_publicKeyPem), out _);

	/// <summary>
	/// Validates a token with the key from a resolver.
	/// </summary>
	[Benchmark]
	public bool ValidateTokenAsync_Resolver() =>
		_validator.ValidateTokenAsync<BenchmarkPayload>(_token, CancellationToken.None).AsTask().GetAwaiter().GetResult().IsValid;

	/// <summary>
	/// Writes a key structure to PEM text.
	/// </summary>
	/// <param name="key">The key structure to write.</param>
	/// <returns>The PEM text.</returns>
	private static string ToPem(object key)
	{
		using var writer = new StringWriter();
		var pemWriter = new PemWriter(writer);
		pemWriter.WriteObject(key);
		pemWriter.Writer.Flush();

		return writer.ToString();
	}

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
