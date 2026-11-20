using System;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Utilities.Jwt.Ed25519.Enums;
using Utilities.Jwt.Ed25519.Interfaces;
using Utilities.Jwt.Ed25519.Models;
using Utilities.Jwt.Ed25519.Options;

namespace Utilities.Jwt.Ed25519.Services;

/// <summary>
/// Validates JWTs signed with an Ed25519 private key.
/// </summary>
/// <param name="keyResolver">
/// The resolver for <see cref="ValidateTokenAsync{T}"/>, or <see langword="null"/> when only <see cref="TryValidateToken{T}"/> is in use.
/// </param>
/// <param name="options">The validation options, or <see langword="null"/> for the default options.</param>
/// <param name="timeProvider">The clock, or <see langword="null"/> for <see cref="TimeProvider.System"/>.</param>
public sealed class JwtValidator(
	IJwtKeyResolver? keyResolver,
	IOptions<JwtValidationOptions>? options,
	TimeProvider? timeProvider) : IJwtValidator
{
	private readonly IJwtKeyResolver? _keyResolver = keyResolver;
	private readonly JwtValidationOptions _options = options?.Value ?? new JwtValidationOptions();
	private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

	/// <summary>
	/// Creates a validator without a resolver, with the default options and the system clock.
	/// Use <see cref="TryValidateToken{T}"/> with this validator.
	/// </summary>
	public JwtValidator()
		: this(null, null, null)
	{
	}

	/// <inheritdoc />
	public bool TryValidateToken<T>(string token, Ed25519PublicKeyParameters publicKey, [NotNullWhen(true)] out T? payload)
		where T : IBaseJwtPayload
	{
		payload = default;

		if (!TokenParts.TryParse(token, out var parts))
			return false;

		// Verify the signature first. The caller gives the key, so the header is not needed before this check.
		if (!VerifySignature(parts, publicKey))
			return false;

		if (JwtContentReader.ReadHeader(parts.Header, out _) != JwtValidationError.None)
			return false;

		var result = CheckVerifiedPayload<T>(parts, null);

		if (!result.IsValid || result.Payload == null)
			return false;

		// Set the payload only after all checks pass. A false result never carries claims.
		payload = result.Payload;
		return true;
	}

	/// <inheritdoc />
	public async ValueTask<JwtValidationResult<T>> ValidateTokenAsync<T>(string token, CancellationToken cancellationToken)
		where T : IBaseJwtPayload
	{
		if (_keyResolver == null)
			throw new InvalidOperationException("ValidateTokenAsync needs an IJwtKeyResolver. Register one with AddJwtEd25519().AddValidation().");

		if (!TokenParts.TryParse(token, out var parts))
			return JwtValidationResult<T>.Failure(JwtValidationError.InvalidFormat);

		// Read the header before the signature check. The resolver needs kid to select the key.
		// A changed kid selects a key that does not match the signature, so the selection is safe.
		var headerError = JwtContentReader.ReadHeader(parts.Header, out var keyId);

		if (headerError != JwtValidationError.None)
			return JwtValidationResult<T>.Failure(headerError);

		if (!JwtContentReader.TryReadUnverifiedClaims(parts.Payload, out var issuer, out var subject))
			return JwtValidationResult<T>.Failure(JwtValidationError.InvalidFormat);

		var context = new JwtKeyResolutionContext(keyId, issuer, subject);
		var key = await _keyResolver.ResolvePublicKeyAsync(context, cancellationToken).ConfigureAwait(false);

		// Do not use a fallback key. A missing key rejects the token.
		if (key == null)
			return JwtValidationResult<T>.Failure(JwtValidationError.KeyNotFound);

		if (!VerifySignature(parts, key.PublicKey))
			return JwtValidationResult<T>.Failure(JwtValidationError.InvalidSignature);

		return CheckVerifiedPayload<T>(parts, key.ExpectedSubject);
	}

	/// <summary>
	/// Checks the claims of a token with a verified signature and reads its payload.
	/// </summary>
	/// <typeparam name="T">The payload type.</typeparam>
	/// <param name="parts">The decoded token parts.</param>
	/// <param name="expectedSubject">The <c>sub</c> value that the key requires, or <see langword="null"/> for no check.</param>
	/// <returns>The validation result.</returns>
	private JwtValidationResult<T> CheckVerifiedPayload<T>(TokenParts parts, string? expectedSubject)
		where T : IBaseJwtPayload
	{
		var error = JwtContentReader.CheckClaims(parts.Payload, _timeProvider.GetUtcNow(), _options, expectedSubject);

		if (error != JwtValidationError.None)
			return JwtValidationResult<T>.Failure(error);

		try
		{
			var payload = JsonSerializer.Deserialize<T>(parts.Payload);

			return payload == null
				? JwtValidationResult<T>.Failure(JwtValidationError.InvalidFormat)
				: JwtValidationResult<T>.Success(payload);
		}
		catch (JsonException)
		{
			return JwtValidationResult<T>.Failure(JwtValidationError.InvalidFormat);
		}
	}

	/// <summary>
	/// Verifies the token signature with the Ed25519 public key.
	/// </summary>
	/// <param name="parts">The decoded token parts.</param>
	/// <param name="publicKey">The Ed25519 public key.</param>
	/// <returns>True if the signature is valid; otherwise, false.</returns>
	private static bool VerifySignature(TokenParts parts, Ed25519PublicKeyParameters publicKey)
	{
		var bytes = Encoding.ASCII.GetBytes(parts.SignedData);
		var verifier = new Ed25519Signer();
		verifier.Init(false, publicKey);
		verifier.BlockUpdate(bytes, 0, bytes.Length);

		return verifier.VerifySignature(parts.Signature);
	}
}
