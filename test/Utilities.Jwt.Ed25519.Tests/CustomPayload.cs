using System.Text.Json.Serialization;
using Utilities.Jwt.Ed25519.Models;

namespace Utilities.Jwt.Ed25519.Tests;

/// <summary>
/// A payload with one custom claim for the tests.
/// </summary>
public sealed class CustomPayload : BaseJwtPayload
{
	[JsonPropertyName("custom_claim")]
	public string? CustomClaim { get; set; }
}
