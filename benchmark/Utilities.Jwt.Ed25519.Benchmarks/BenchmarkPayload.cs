using System.Text.Json.Serialization;
using Utilities.Jwt.Ed25519.Models;

namespace Utilities.Jwt.Ed25519.Benchmarks;

/// <summary>
/// The payload of the benchmark tokens. The payload has all registered claims and one custom claim.
/// </summary>
public sealed class BenchmarkPayload : BaseJwtPayload
{
	/// <summary>
	/// Gets or sets the custom claim.
	/// </summary>
	[JsonPropertyName("custom_claim")]
	public string? CustomClaim { get; set; }
}
