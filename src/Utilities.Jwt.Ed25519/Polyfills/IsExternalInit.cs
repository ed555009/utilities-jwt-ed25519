namespace System.Runtime.CompilerServices;

/// <summary>
/// Lets the compiler use <c>init</c> accessors and records on netstandard2.1.
/// </summary>
/// <remarks>
/// netstandard2.1 does not have this type. The compiler needs it for <c>init</c> and positional records.
/// </remarks>
internal static class IsExternalInit
{
}
