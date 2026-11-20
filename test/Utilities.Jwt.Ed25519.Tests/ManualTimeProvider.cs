namespace Utilities.Jwt.Ed25519.Tests;

/// <summary>
/// A clock with a time that the test sets. The tests use it to check the exact second of each time boundary.
/// </summary>
/// <param name="now">The start time.</param>
internal sealed class ManualTimeProvider(DateTimeOffset now) : TimeProvider
{
	/// <summary>
	/// Gets or sets the current time.
	/// </summary>
	public DateTimeOffset Now { get; set; } = now;

	/// <inheritdoc />
	public override DateTimeOffset GetUtcNow() => Now;
}
