using System.Text.Json;

namespace Utilities.Jwt.Ed25519.Models
{
	/// <summary>
	/// Represents the header of a JWT (JSON Web Token) with predefined algorithm and type.
	/// </summary>
	public static class JwtHeader
	{
		/// <summary>
		/// Gets the algorithm used for the JWT, which is "EdDSA".
		/// </summary>
		public static string Algorithm => "EdDSA";

		/// <summary>
		/// Gets the type of the token, which is "JWT".
		/// </summary>
		public static string Type => "JWT";

		/// <summary>
		/// Exports the JWT header as a JSON string.
		/// </summary>
		/// <returns>A JSON string representing the JWT header.</returns>
		public static string Export() =>
			JsonSerializer.Serialize(
				new
				{
					alg = Algorithm,
					typ = Type
				});
	}
}
