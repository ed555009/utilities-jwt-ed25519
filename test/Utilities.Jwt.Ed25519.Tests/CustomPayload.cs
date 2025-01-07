using System.Text.Json.Serialization;
using Utilities.Jwt.Ed25519.Models;

namespace Utilities.Jwt.Ed25519.Tests;

public class CustomPayload : BaseJwtPayload
{
	[JsonPropertyName("custom_claim")]
	public string? CustomClaim { get; set; }
}
