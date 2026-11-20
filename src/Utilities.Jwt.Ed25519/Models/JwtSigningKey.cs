using Org.BouncyCastle.Crypto.Parameters;

namespace Utilities.Jwt.Ed25519.Models;

/// <summary>
/// A private key that signs tokens, with its key ID.
/// </summary>
/// <param name="KeyId">The key ID that the signer writes to the <c>kid</c> header, or <see langword="null"/> for no <c>kid</c>.</param>
/// <param name="PrivateKey">The Ed25519 private key.</param>
public sealed record JwtSigningKey(string? KeyId, Ed25519PrivateKeyParameters PrivateKey);
