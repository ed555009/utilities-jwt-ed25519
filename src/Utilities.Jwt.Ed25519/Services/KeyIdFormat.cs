namespace Utilities.Jwt.Ed25519.Services;

/// <summary>
/// Checks the format of a key ID (<c>kid</c>).
/// </summary>
/// <remarks>
/// A resolver can use the key ID as a database key or a file name.
/// The format rule blocks injection and path traversal before the resolver gets the value.
/// </remarks>
internal static class KeyIdFormat
{
	/// <summary>
	/// The maximum length of a key ID.
	/// </summary>
	public const int MaxLength = 128;

	/// <summary>
	/// Checks that the key ID has 1 to <see cref="MaxLength"/> characters from <c>[A-Za-z0-9._:-]</c>.
	/// </summary>
	/// <param name="keyId">The key ID to check.</param>
	/// <returns>True if the key ID has the format; otherwise, false.</returns>
	public static bool IsValid(string? keyId)
	{
		if (string.IsNullOrEmpty(keyId) || keyId!.Length > MaxLength)
			return false;

		foreach (var c in keyId)
		{
			if (!(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c is '.' or '_' or ':' or '-'))
				return false;
		}

		return true;
	}
}
