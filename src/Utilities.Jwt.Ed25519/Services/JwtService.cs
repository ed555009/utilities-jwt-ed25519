using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
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
		/// Builds a JWT token from the given payload and private key parameters.
		/// </summary>
		/// <typeparam name="T">The type of the JWT payload, which must implement IBaseJwtPayload.</typeparam>
		/// <param name="jwtPayload">The JWT payload to include in the token.</param>
		/// <param name="privateKeyParameters">The Ed25519 private key parameters used to sign the token.</param>
		/// <returns>A JWT token as a string.</returns>
		public static string BuildToken<T>(T jwtPayload, Ed25519PrivateKeyParameters privateKeyParameters)
			where T : IBaseJwtPayload
		{
			var payload = Base64UrlEncode(Encoding.UTF8.GetBytes(
				JsonSerializer.Serialize(jwtPayload, new JsonSerializerOptions
				{
					DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
				})));
			var data = $"{GetEncodedHeader()}.{payload}";
			var signature = GetEncodedSignature(data, privateKeyParameters);

			return $"{data}.{signature}";
		}

		/// <summary>
		/// Validates a JWT token using the provided Ed25519 public key parameters.
		/// </summary>
		/// <typeparam name="T">The type of the JWT payload, which must implement <see cref="IBaseJwtPayload"/>.</typeparam>
		/// <param name="token">The JWT token to validate.</param>
		/// <param name="publicKeyParameters">The Ed25519 public key parameters used to verify the token's signature.</param>
		/// <param name="payload">The deserialized JWT payload if the token is valid; otherwise, the default value of <typeparamref name="T"/>.</param>
		/// <returns>True if the token is valid; otherwise, false.</returns>
		public static bool ValidateToken<T>(string token, Ed25519PublicKeyParameters publicKeyParameters, out T payload)
			where T : IBaseJwtPayload
		{
			var parts = ParseToken(token);
			var data = $"{parts.Header}.{parts.Payload}";
			var isValidSignature = VerifySignature(data, parts.DecodedSignature, publicKeyParameters);
			var header = JsonSerializer.Deserialize<Dictionary<string, string>>(parts.DecodedHeader);
			payload = JsonSerializer.Deserialize<T>(parts.DecodedPayload)!;

			return isValidSignature
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
		/// Parses a JWT token into its constituent parts: header, payload, and signature.
		/// </summary>
		/// <param name="token">The JWT token to parse.</param>
		/// <returns>A <see cref="TokenParts"/> object containing the header, payload, and signature of the token.</returns>
		/// <exception cref="InvalidDataException">
		/// Thrown if the token format is invalid or if any part of the token (header, payload, or signature) is null.
		/// </exception>
		static TokenParts ParseToken(string token)
		{
			var parts = token.Split('.');

			if (parts.Length != 3)
				throw new InvalidDataException("Invalid JWT token format");

			return new TokenParts
			{
				Header = parts[0],
				Payload = parts[1],
				Signature = parts[2]
			};
		}

		/// <summary>
		/// Encodes the JWT header to a Base64 URL encoded string.
		/// </summary>
		/// <returns>A Base64 URL encoded string representing the JWT header.</returns>
		static string GetEncodedHeader() =>
			Base64UrlEncode(Encoding.UTF8.GetBytes(JwtHeader.Export()));

		/// <summary>
		/// Generates and encodes the JWT signature to a Base64 URL encoded string.
		/// </summary>
		/// <param name="data">The data to be signed.</param>
		/// <param name="privateKeyParameters">The Ed25519 private key parameters used to sign the data.</param>
		/// <returns>A Base64 URL encoded string representing the JWT signature.</returns>
		static string GetEncodedSignature(string data, Ed25519PrivateKeyParameters privateKeyParameters)
		{
			var signer = new Ed25519Signer();
			signer.Init(true, privateKeyParameters);
			signer.BlockUpdate(Encoding.UTF8.GetBytes(data), 0, data.Length);

			return Base64UrlEncode(signer.GenerateSignature());
		}

		/// <summary>
		/// Verifies the JWT signature using the provided Ed25519 public key parameters.
		/// </summary>
		/// <param name="data">The data to be verified.</param>
		/// <param name="signature">The signature to verify.</param>
		/// <param name="publicKeyParameters">The Ed25519 public key parameters used to verify the signature.</param>
		/// <returns>True if the signature is valid; otherwise, false.</returns>
		static bool VerifySignature(string data, byte[] signature, Ed25519PublicKeyParameters publicKeyParameters)
		{
			var verifier = new Ed25519Signer();
			verifier.Init(false, publicKeyParameters);
			verifier.BlockUpdate(Encoding.UTF8.GetBytes(data), 0, data.Length);

			return verifier.VerifySignature(signature);
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
		public static byte[] Base64UrlDecode(string data) =>
			Convert.FromBase64String(data
				.Replace('-', '+')
				.Replace('_', '/')
				.PadRight(data.Length + (4 - data.Length % 4) % 4, '='));
	}
}
