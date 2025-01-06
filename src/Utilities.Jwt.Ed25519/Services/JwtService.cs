using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.OpenSsl;
using Utilities.Jwt.Ed25519.Enums;
using Utilities.Jwt.Ed25519.Interfaces;
using Utilities.Jwt.Ed25519.Models;

namespace Utilities.Jwt.Ed25519.Services
{
	public class JwtService : IJwtService
	{
		/// <summary>
		/// Builds a JWT token using the provided payload and Ed25519 private key parameters.
		/// </summary>
		/// <param name="jwtPayload">The payload to include in the JWT token.</param>
		/// <param name="privateKeyParameters">The Ed25519 private key parameters used to sign the token.</param>
		/// <returns>A JWT token as a string.</returns>
		public static string BuildToken(JwtPayload jwtPayload, Ed25519PrivateKeyParameters privateKeyParameters)
		{
			var header = Base64UrlEncode(Encoding.UTF8.GetBytes(JwtHeader.Export()));
			var payload = Base64UrlEncode(Encoding.UTF8.GetBytes(jwtPayload.Export()));
			var data = $"{header}.{payload}";
			var signer = new Ed25519Signer();
			signer.Init(true, privateKeyParameters);
			signer.BlockUpdate(Encoding.UTF8.GetBytes(data), 0, data.Length);
			var signature = Base64UrlEncode(signer.GenerateSignature());

			return $"{data}.{signature}";
		}

		/// <summary>
		/// Validates a JWT token using the provided Ed25519 public key parameters.
		/// </summary>
		/// <param name="token">The JWT token to validate.</param>
		/// <param name="publicKeyParameters">The Ed25519 public key parameters used for validation.</param>
		/// <param name="payload">
		/// When this method returns, contains the payload of the JWT token if the token is valid;
		/// otherwise, null. This parameter is passed uninitialized.
		/// </param>
		/// <returns>
		/// <c>true</c> if the token is valid and the signature matches; otherwise, <c>false</c>.
		/// </returns>
		/// <exception cref="ArgumentNullException">Thrown if the token or publicKeyParameters is null.</exception>
		/// <exception cref="FormatException">Thrown if the token format is invalid.</exception>
		public static bool ValidateToken(
			string token,
			Ed25519PublicKeyParameters publicKeyParameters,
			out Dictionary<string, object>? payload)
		{
			var parts = token.Split('.');
			var data = $"{parts[0]}.{parts[1]}";
			var header = JsonSerializer.Deserialize<Dictionary<string, string>>(
				Encoding.UTF8.GetString(Base64UrlDecode(parts[0])));
			payload = JsonSerializer.Deserialize<Dictionary<string, object>>(
			   Encoding.UTF8.GetString(Base64UrlDecode(parts[1])));
			var signature = Base64UrlDecode(parts[2]);
			var verifier = new Ed25519Signer();
			verifier.Init(false, publicKeyParameters);
			verifier.BlockUpdate(Encoding.UTF8.GetBytes(data), 0, data.Length);

			return verifier.VerifySignature(signature)
				&& header != null
				&& header["alg"] == JwtHeader.Algorithm
				&& header["typ"] == JwtHeader.Type;
		}

		/// <summary>
		/// Loads an Ed25519 private key from a given string or file path.
		/// </summary>
		/// <param name="dataOrPath">The string containing the key data or the file path to the key.</param>
		/// <param name="loadKeyType">Specifies whether the key is provided as a string or a file path. Default is <see cref="LoadKeyType.String"/>.</param>
		/// <returns>An instance of <see cref="Ed25519PrivateKeyParameters"/> representing the loaded private key.</returns>
		/// <exception cref="InvalidDataException">Thrown when the provided key data is not a valid Ed25519 private key format.</exception>
		public static Ed25519PrivateKeyParameters LoadPrivateKey(
			string dataOrPath,
			LoadKeyType loadKeyType = LoadKeyType.String)
		{
			var pemObject = loadKeyType == LoadKeyType.String ? FromString(dataOrPath) : FromFile(dataOrPath);

			if (pemObject is Ed25519PrivateKeyParameters privateKeyParameters)
				return privateKeyParameters;

			throw new InvalidDataException("Invalid Ed25519 private key format");
		}

		/// <summary>
		/// Loads an Ed25519 public key from a given string or file path.
		/// </summary>
		/// <param name="dataOrPath">The public key data as a string or the file path to the public key.</param>
		/// <param name="loadKeyType">Specifies whether the input is a string or a file path. Default is <see cref="LoadKeyType.String"/>.</param>
		/// <returns>An instance of <see cref="Ed25519PublicKeyParameters"/> representing the loaded public key.</returns>
		/// <exception cref="InvalidDataException">Thrown when the provided data does not represent a valid Ed25519 public key.</exception>
		public static Ed25519PublicKeyParameters LoadPublicKey(
			string dataOrPath,
			LoadKeyType loadKeyType = LoadKeyType.String)
		{
			var pemObject = loadKeyType == LoadKeyType.String ? FromString(dataOrPath) : FromFile(dataOrPath);

			if (pemObject is Ed25519PublicKeyParameters publicKeyParameters)
				return publicKeyParameters;

			throw new InvalidDataException("Invalid Ed25519 public key format");
		}

		/// <summary>
		/// Reads a PEM encoded object from a string.
		/// </summary>
		/// <param name="data">The string containing the PEM encoded data.</param>
		/// <returns>The object read from the PEM encoded string.</returns>
		static object FromString(string data)
		{
			using var stringReader = new StringReader(data);
			return new PemReader(stringReader).ReadObject();
		}

		/// <summary>
		/// Reads an object from a PEM file at the specified path.
		/// </summary>
		/// <param name="path">The file path to the PEM file.</param>
		/// <returns>The object read from the PEM file.</returns>
		static object FromFile(string path)
		{
			using var fileReader = File.OpenText(path);
			return new PemReader(fileReader).ReadObject();
		}

		/// <summary>
		/// Encodes the specified byte array to a Base64 URL encoded string.
		/// </summary>
		/// <param name="data">The byte array to encode.</param>
		/// <returns>A Base64 URL encoded string representation of the input byte array.</returns>
		static string Base64UrlEncode(byte[] data) =>
			Convert.ToBase64String(data)
				.Replace('+', '-')
				.Replace('/', '_')
				.Replace("=", "");

		/// <summary>
		/// Decodes a Base64 URL encoded string to a byte array.
		/// </summary>
		/// <param name="data">The Base64 URL encoded string to decode.</param>
		/// <returns>A byte array representing the decoded data.</returns>
		/// <remarks>
		/// This method replaces URL-safe characters ('-' and '_') with Base64 characters ('+' and '/')
		/// and pads the string with '=' characters to ensure it has a length that is a multiple of 4.
		/// </remarks>
		static byte[] Base64UrlDecode(string data) =>
			Convert.FromBase64String(data
				.Replace('-', '+')
				.Replace('_', '/')
				.PadRight(data.Length + (4 - data.Length % 4) % 4, '='));
	}
}
