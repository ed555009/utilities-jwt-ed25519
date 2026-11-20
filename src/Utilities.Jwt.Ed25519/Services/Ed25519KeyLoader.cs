using System.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Utilities.Jwt.Ed25519.Enums;

namespace Utilities.Jwt.Ed25519.Services;

/// <summary>
/// Loads Ed25519 keys from PEM strings or PEM files.
/// </summary>
public static class Ed25519KeyLoader
{
	/// <summary>
	/// Loads an Ed25519 private key from a PEM string or a PEM file.
	/// </summary>
	/// <param name="dataOrPath">The PEM string, or the path of the PEM file.</param>
	/// <param name="loadKeyType">The type of <paramref name="dataOrPath"/>. The default is <see cref="LoadKeyType.String"/>.</param>
	/// <returns>The Ed25519 private key.</returns>
	/// <exception cref="InvalidDataException">Thrown when the PEM data is not an Ed25519 private key.</exception>
	public static Ed25519PrivateKeyParameters LoadPrivateKey(string dataOrPath, LoadKeyType loadKeyType = LoadKeyType.String)
	{
		if (ReadPemObject(dataOrPath, loadKeyType) is Ed25519PrivateKeyParameters privateKey)
			return privateKey;

		throw new InvalidDataException("Invalid Ed25519 private key format");
	}

	/// <summary>
	/// Loads an Ed25519 public key from a PEM string or a PEM file.
	/// </summary>
	/// <param name="dataOrPath">The PEM string, or the path of the PEM file.</param>
	/// <param name="loadKeyType">The type of <paramref name="dataOrPath"/>. The default is <see cref="LoadKeyType.String"/>.</param>
	/// <returns>The Ed25519 public key.</returns>
	/// <exception cref="InvalidDataException">Thrown when the PEM data is not an Ed25519 public key.</exception>
	public static Ed25519PublicKeyParameters LoadPublicKey(string dataOrPath, LoadKeyType loadKeyType = LoadKeyType.String)
	{
		if (ReadPemObject(dataOrPath, loadKeyType) is Ed25519PublicKeyParameters publicKey)
			return publicKey;

		throw new InvalidDataException("Invalid Ed25519 public key format");
	}

	/// <summary>
	/// Reads the first PEM object from a PEM string or a PEM file.
	/// </summary>
	/// <param name="dataOrPath">The PEM string, or the path of the PEM file.</param>
	/// <param name="loadKeyType">The type of <paramref name="dataOrPath"/>.</param>
	/// <returns>The PEM object, or <see langword="null"/> when the data has no PEM object.</returns>
	private static object? ReadPemObject(string dataOrPath, LoadKeyType loadKeyType)
	{
		using TextReader reader = loadKeyType == LoadKeyType.String
			? new StringReader(dataOrPath)
			: File.OpenText(dataOrPath);

		return new PemReader(reader).ReadObject();
	}
}
