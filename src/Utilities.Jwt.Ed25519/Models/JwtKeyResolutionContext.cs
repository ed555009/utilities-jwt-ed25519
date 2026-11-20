namespace Utilities.Jwt.Ed25519.Models;

/// <summary>
/// The token data that a key resolver can use to select a public key.
/// </summary>
/// <remarks>
/// WARNING: The validator has not verified the signature yet. Use these values only to select a key.
/// Do not use them for any other decision.
/// </remarks>
/// <param name="KeyId">The <c>kid</c> header, or <see langword="null"/> when the token has no <c>kid</c>.</param>
/// <param name="UnverifiedIssuer">The <c>iss</c> claim before signature verification, or <see langword="null"/>.</param>
/// <param name="UnverifiedSubject">The <c>sub</c> claim before signature verification, or <see langword="null"/>.</param>
public sealed record JwtKeyResolutionContext(string? KeyId, string? UnverifiedIssuer, string? UnverifiedSubject);
