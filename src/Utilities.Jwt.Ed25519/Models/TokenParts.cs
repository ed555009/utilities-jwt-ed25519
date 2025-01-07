using System.Text;
using Utilities.Jwt.Ed25519.Services;

namespace Utilities.Jwt.Ed25519.Models
{
	/// <summary>
	/// Represents the parts of a JWT (JSON Web Token).
	/// </summary>
	public class TokenParts
	{
		/// <summary>
		/// Gets or sets the encoded header of the JWT.
		/// </summary>
		public string? Header { get; set; }

		/// <summary>
		/// Gets or sets the encoded payload of the JWT.
		/// </summary>
		public string? Payload { get; set; }

		/// <summary>
		/// Gets or sets the encoded signature of the JWT.
		/// </summary>
		public string? Signature { get; set; }

		/// <summary>
		/// Gets the decoded header of the JWT.
		/// </summary>
		public string DecodedHeader =>
			Header == null ? "{}" : Encoding.UTF8.GetString(JwtService.Base64UrlDecode(Header));

		/// <summary>
		/// Gets the decoded payload of the JWT.
		/// </summary>
		public string DecodedPayload =>
			Payload == null ? "{}" : Encoding.UTF8.GetString(JwtService.Base64UrlDecode(Payload));

		/// <summary>
		/// Gets the decoded signature of the JWT.
		/// </summary>
		public byte[] DecodedSignature =>
			Signature == null ? new byte[0] : JwtService.Base64UrlDecode(Signature);
	}
}
