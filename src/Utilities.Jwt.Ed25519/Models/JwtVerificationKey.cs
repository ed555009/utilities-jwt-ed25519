using Org.BouncyCastle.Crypto.Parameters;

namespace Utilities.Jwt.Ed25519.Models;

/// <summary>
/// A public key that verifies tokens, with an optional subject binding.
/// </summary>
/// <param name="PublicKey">The Ed25519 public key.</param>
/// <param name="ExpectedSubject">
/// The <c>sub</c> value that a token for this key must have, or <see langword="null"/> for no subject check.
/// Set it when one key belongs to one member, so that member A cannot sign a token for member B.
/// </param>
public sealed record JwtVerificationKey(Ed25519PublicKeyParameters PublicKey, string? ExpectedSubject = null);
