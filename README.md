# Utilities.Jwt.Ed25519

[![GitHub](https://img.shields.io/github/license/ed555009/utilities-jwt-ed25519)](LICENSE)
[![Build Status](https://github.com/ed555009/utilities-jwt-ed25519/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/ed555009/utilities-jwt-ed25519/actions/workflows/build.yml)
[![Nuget](https://img.shields.io/nuget/v/Utilities.Jwt.Ed25519)](https://www.nuget.org/packages/Utilities.Jwt.Ed25519)

![Coverage](https://sonarcloud.io/api/project_badges/measure?project=utilities-jwt-ed25519&metric=coverage)
![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=utilities-jwt-ed25519&metric=alert_status)
![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=utilities-jwt-ed25519&metric=reliability_rating)
![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=utilities-jwt-ed25519&metric=security_rating)
![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=utilities-jwt-ed25519&metric=vulnerabilities)

This library provides a lightweight implementation for generating and validating JSON Web Tokens (JWTs) using the Ed25519 public-private key algorithm ([RFC8032](https://datatracker.ietf.org/doc/html/rfc8032)). It supports the registered JWT claims ([RFC7519](https://datatracker.ietf.org/doc/html/rfc7519)) `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti` and allows users to dynamically add custom claims.

This library also works with generic payloads class implementing the `IBaseJwtPayload` interface.


## Ed25519 Key Algorithm Overview
Ed25519 is a modern, highly efficient digital signature scheme based on the **Edwards-curve Digital Signature Algorithm (EdDSA)**. It is designed to provide fast signing and verification while ensuring strong security. Ed25519 is especially well-suited for use cases where performance, key size, and security are critical, ideal for scenarios requiring fast signing and verification, small key sizes, and strong security. It is particularly efficient in resource-constrained environments like IoT devices and mobile applications.

### Key Features

- **High Speed**: Fast cryptographic operations for both signing and verifying signatures.

- **Compact Key Size**: 32-byte private keys and 32-byte public keys for minimal storage and transmission overhead.

- **Deterministic**: Produces the same signature for the same input, eliminating randomness issues.

- **Resistant to Side-Channel Attacks**: Designed to mitigate timing and power analysis attacks.

- **Robust Security**: Provides 128-bit security strength, equivalent to RSA-3072 or higher.

### Ed25519 in Cryptographic Standards
- Defined in **RFC8032**: *Edwards-Curve Digital Signature Algorithm (EdDSA)*.

- Widely adopted in modern cryptographic libraries and protocols such as OpenSSH, Signal, and more.

### Comparison with Symmetric Signing (e.g., HMAC)

| Feature               | Ed25519                          | Symmetric Signing (HMAC)       |
|-----------------------|----------------------------------|---------------------------------|
| **Key Type**          | Public-Private Key Pair         | Single Secret Key              |
| **Key Sharing**       | Only the public key is shared   | Secret key must be shared      |
| **Security**          | Stronger, resistant to key exposure | Less secure if key is leaked  |
| **Use Case**          | Suitable for distributed systems (e.g., microservices) | Better for single-system scenarios |
| **Performance**       | Slightly slower due to key pair computation | Faster due to simpler operations |

### Comparison with RSA (e.g., RSA2048, RSA4096)

| Feature               | Ed25519                          | RSA                            |
|-----------------------|----------------------------------|---------------------------------|
| **Algorithm**         | Edwards-curve Digital Signature Algorithm (EdDSA) | RSA (asymmetric encryption)    |
| **Key Size**          | Compact (32-byte private key, 32-byte public key) | Large (2048-bit or 4096-bit keys) |
| **Performance**       | Faster signing and verification | Slower due to large key sizes  |
| **Security**          | Equivalent security with smaller key size | Equivalent security, larger keys |

### Why Choose Ed25519?
1. **High Performance**: Ed25519 offers much faster signing and verification compared to RSA, making it ideal for modern applications.

2. **Small Key Size**: The compact keys make storage and transmission more efficient.

3. **Security**: Provides equivalent or better security than RSA with significantly smaller keys.

4. **No Shared Secret**: Unlike symmetric signing methods, Ed25519 uses public-private key pairs, so you only need to distribute the public key securely.



## Installation

```bash
dotnet add package Utilities.Jwt.Ed25519
```

## Upgrade to 10.0

Version 10.0 has breaking changes. The major version follows the .NET version.

### Bouncy Castle package

- Version 10.0 depends on `BouncyCastle.Cryptography`. Versions 8.x depend on `Portable.BouncyCastle`.
- The key types `Ed25519PrivateKeyParameters` and `Ed25519PublicKeyParameters` move from the assembly `BouncyCastle.Crypto` to the assembly `BouncyCastle.Cryptography`. The namespace `Org.BouncyCastle` does not change.
- Recompile your project against version 10.0. A binary that you compiled against version 8.x fails at run time.
- Remove direct references to `Portable.BouncyCastle`. A project with both packages gets compiler error `CS0433`.

### System.Text.Json

- The minimum `System.Text.Json` version changes from 9.0.0 to 10.0.15.

### API

Version 10.0 replaces the static class `JwtService` with 2 interfaces. You can inject and mock the interfaces in your tests.

| Version 8.x | Version 10.0 |
|---|---|
| `JwtService.BuildToken(payload, key)` | `IJwtSigner.BuildToken(payload, key)`, or `new JwtSigner().BuildToken(payload, key)` |
| `JwtService.ValidateToken<T>(token, key, out var payload)` | `IJwtValidator.TryValidateToken<T>(token, key, out var payload)` |
| `JwtService.LoadPrivateKey(...)` | `Ed25519KeyLoader.LoadPrivateKey(...)` |
| `JwtService.LoadPublicKey(...)` | `Ed25519KeyLoader.LoadPublicKey(...)` |
| `JwtService.Base64UrlDecode(...)` | Removed |
| `TokenParts` | Removed from the public API |

### New dependencies

Version 10.0 adds these dependencies for dependency injection and the clock:

- `Microsoft.Extensions.DependencyInjection.Abstractions` 10.0.15
- `Microsoft.Extensions.Options` 10.0.15
- `Microsoft.Extensions.Options.DataAnnotations` 10.0.15
- `Microsoft.Bcl.TimeProvider` 10.0.15

## Using service

### Define custom payload class

Define your payload class by inheriting the `BaseJwtPayload` class.

```csharp
using System.Text.Json.Serialization;

public sealed class MyCustomPayload : BaseJwtPayload
{
	[JsonPropertyName("custom_claim")]
	public string? CustomClaim { get; set; }
}
```

### Build token

```csharp
using Utilities.Jwt.Ed25519.Enums;
using Utilities.Jwt.Ed25519.Interfaces;
using Utilities.Jwt.Ed25519.Services;

// prepare payload
var now = DateTimeOffset.UtcNow;
var payload = new MyCustomPayload
{
	Subject = "Subject",
	Issuer = "Issuer",
	Audience = "Audience",
	Expiration = now.AddMinutes(1).ToUnixTimeSeconds(),
	IssuedAt = now.ToUnixTimeSeconds(),
	NotBefore = now.ToUnixTimeSeconds(),
	JwtId = Guid.NewGuid().ToString(),
	CustomClaim = "CustomClaimValue"
};

// load private key from a PEM string
var privateKey = Ed25519KeyLoader.LoadPrivateKey(privateKeyPem);

// or, load private key from a PEM file
var privateKey = Ed25519KeyLoader.LoadPrivateKey("path/to/private.pem", LoadKeyType.File);

// build token
IJwtSigner signer = new JwtSigner();
var token = signer.BuildToken(payload, privateKey);
```

> **WARNING:** Do not write a private key in source code. Read the key from a secret store.

### Validate token

```csharp
using Utilities.Jwt.Ed25519.Enums;
using Utilities.Jwt.Ed25519.Interfaces;
using Utilities.Jwt.Ed25519.Services;

// load public key from a PEM string
var publicKey = Ed25519KeyLoader.LoadPublicKey(publicKeyPem);

// or, load public key from a PEM file
var publicKey = Ed25519KeyLoader.LoadPublicKey("path/to/public.pem", LoadKeyType.File);

// validate token
IJwtValidator validator = new JwtValidator();

if (validator.TryValidateToken<MyCustomPayload>(token, publicKey, out var payload))
{
	// payload is not null here
}
```

**Note:** `TryValidateToken()` validates the token `signature`, the `alg` and `typ` headers, and the `exp` and `nbf` claims.

- `TryValidateToken()` returns `false` when the current time is at or after `exp`, or before `nbf`. A token without `exp` or `nbf` skips that check.
- `TryValidateToken()` returns `false` for a malformed token. It does not throw an exception.
- When `TryValidateToken()` returns `false`, `payload` is `null`. Do not use `payload` after a `false` result.
- `TryValidateToken()` does not validate the other claims, such as `iss` and `aud`. Check these claims in the payload.

## Dependency injection

`AddJwtEd25519()` registers `IJwtSigner` and `IJwtValidator` as Scoped services. Add a key source for signing, validation, or both.

### One fixed key

```csharp
using Utilities.Jwt.Ed25519.Extensions;

builder.Services.AddJwtEd25519()
	.AddSigning(o =>
	{
		o.PrivateKeyPem = builder.Configuration["Jwt:PrivateKeyPem"]!;
		o.KeyId = "main";
	})
	.AddValidation(o =>
	{
		o.PublicKeyPem = builder.Configuration["Jwt:PublicKeyPem"]!;
		o.KeyId = "main";
	})
	.ConfigureValidation(o => o.ClockSkew = TimeSpan.FromSeconds(30));
```

- The host checks the keys and the options at startup. A key that is not an Ed25519 key stops the host.
- A service that only validates tokens calls `AddValidation()` only. That service never reads a private key.

> **WARNING:** Read the PEM values from a secret store, for example AWS Secrets Manager. Do not put them in `appsettings.json`.

### One key for each member or tenant

Write a resolver when the key depends on the token. The resolver gets the `kid` header and the unverified `iss` and `sub` claims.

```csharp
public sealed class MemberKeyResolver(AppDbContext db) : IJwtKeyResolver
{
	private readonly AppDbContext _db = db;

	public async ValueTask<JwtVerificationKey?> ResolvePublicKeyAsync(
		JwtKeyResolutionContext context, CancellationToken cancellationToken)
	{
		var member = await _db.Members.SingleOrDefaultAsync(m => m.KeyId == context.KeyId, cancellationToken);

		// Return null when no key matches. Do not return a fallback key.
		return member == null
			? null
			: new JwtVerificationKey(Ed25519KeyLoader.LoadPublicKey(member.PublicKeyPem), member.Id);
	}
}

builder.Services.AddJwtEd25519().AddValidation<MemberKeyResolver>();
```

- A custom resolver is Scoped. It can use a Scoped `DbContext`.
- Set `ExpectedSubject` to bind the key to one member. The validator then rejects a token from member A with `sub` = member B.
- A signing resolver (`IJwtSigningKeyResolver`) works the same way for signing. Register it with `AddSigning<TResolver>()`.

### Validate with the resolver

```csharp
var result = await validator.ValidateTokenAsync<MyCustomPayload>(token, cancellationToken);

if (!result.IsValid)
{
	// Log result.Error. Do not return result.Error to the client.
	return Results.Unauthorized();
}
```

### Options

| Option | Default | Rule |
|---|---|---|
| `JwtValidationOptions.ClockSkew` | 0 | 0 to 5 minutes. The validator adds the value to `exp` and removes it from `nbf`. |
| `JwtValidationOptions.RequireExpiration` | `false` | `true` rejects a token without `exp`. |
| `StaticSigningKeyOptions.KeyId` | `null` | The signer writes the value to the `kid` header. |
| `StaticValidationKeyOptions.KeyId` | `null` | When set, the validator accepts only tokens with the same `kid`. |

### Validation rules

- `alg` must be `EdDSA` and `typ` must be `JWT`. The token cannot select the algorithm.
- The validator rejects a header with `crit`.
- The validator never reads the `jwk`, `jku`, `x5u` or `x5c` headers. A token cannot give its own key.
- `kid` must be 1 to 128 characters from `[A-Za-z0-9._:-]`. The validator checks the format before the resolver gets the value.
- `JwtValidationResult.Error` shows why a token failed. Use it for logs and tests only. The value shows which key IDs exist.

## Benchmark

The benchmark project is in `benchmark/Utilities.Jwt.Ed25519.Benchmarks`. Run it with this command:

```bash
cd benchmark/Utilities.Jwt.Ed25519.Benchmarks
dotnet run -c Release -f net10.0 -- --filter '*' --runtimes net8.0 net10.0
```

The benchmark has 2 scenarios:

- `PreloadedKey`: the benchmark loads the key once. The dependency injection registration of version 10.0 loads the key once too.
- `LoadKeyEachCall`: the benchmark parses the PEM key in each call. The 8.x results used this scenario.

### Version 10.0

```
BenchmarkDotNet v0.15.8, macOS 27.0.1 (26A434) [Darwin 27.0.0]
Apple M3 Pro, 1 CPU, 11 logical and 11 physical cores
.NET SDK 11.0.100
  [Host]    : .NET 10.0.15 (10.0.15, 10.0.1526.53008), Arm64 RyuJIT armv8.0-a
  .NET 10.0 : .NET 10.0.15 (10.0.15, 10.0.1526.53008), Arm64 RyuJIT armv8.0-a
  .NET 8.0  : .NET 8.0.6 (8.0.6, 8.0.624.26715), Arm64 RyuJIT armv8.0-a
```

| Method                        | Runtime   | Mean     | Error    | StdDev   | Allocated |
|------------------------------ |---------- |---------:|---------:|---------:|----------:|
| BuildToken_PreloadedKey       | .NET 10.0 | 23.42 μs | 0.464 μs | 0.587 μs |   6.98 KB |
| BuildToken_PreloadedKey       | .NET 8.0  | 24.02 μs | 0.125 μs | 0.111 μs |   6.99 KB |
| ValidateToken_PreloadedKey    | .NET 10.0 | 42.62 μs | 0.844 μs | 1.183 μs |   9.73 KB |
| ValidateToken_PreloadedKey    | .NET 8.0  | 44.53 μs | 0.655 μs | 0.612 μs |   9.92 KB |
| BuildToken_LoadKeyEachCall    | .NET 10.0 | 46.74 μs | 0.604 μs | 0.565 μs |  15.96 KB |
| BuildToken_LoadKeyEachCall    | .NET 8.0  | 47.84 μs | 0.098 μs | 0.092 μs |  15.96 KB |
| ValidateToken_LoadKeyEachCall | .NET 10.0 | 50.59 μs | 0.952 μs | 1.019 μs |  17.13 KB |
| ValidateToken_LoadKeyEachCall | .NET 8.0  | 52.60 μs | 0.886 μs | 0.828 μs |  17.13 KB |
| ValidateTokenAsync_Resolver   | .NET 10.0 | 43.76 μs | 0.088 μs | 0.082 μs |  10.13 KB |
| ValidateTokenAsync_Resolver   | .NET 8.0  | 44.10 μs | 0.430 μs | 0.402 μs |   9.98 KB |

### Comparison with version 8.0.973

The same machine ran version 8.0.973 with the same benchmark scenarios on the same day.

| Operation | Runtime | Scenario | 8.0.973 | 10.0 | Time | Memory |
|---|---|---|---|---|---:|---:|
| Build | .NET 8.0 | LoadKeyEachCall | 53.60 μs / 68.00 KB | 47.84 μs / 15.96 KB | -10.7% | -76.5% |
| Validate | .NET 8.0 | LoadKeyEachCall | 70.31 μs / 134.77 KB | 52.60 μs / 17.13 KB | -25.2% | -87.3% |
| Build | .NET 10.0 | LoadKeyEachCall | 51.04 μs / 67.54 KB | 46.74 μs / 15.96 KB | -8.4% | -76.4% |
| Validate | .NET 10.0 | LoadKeyEachCall | 67.61 μs / 133.67 KB | 50.59 μs / 17.13 KB | -25.2% | -87.2% |
| Build | .NET 8.0 | PreloadedKey | 26.23 μs / 30.03 KB | 24.02 μs / 6.99 KB | -8.4% | -76.7% |
| Validate | .NET 8.0 | PreloadedKey | 65.96 μs / 122.35 KB | 44.53 μs / 9.92 KB | -32.5% | -91.9% |
| Build | .NET 10.0 | PreloadedKey | 24.16 μs / 29.75 KB | 23.42 μs / 6.98 KB | -3.1% | -76.5% |
| Validate | .NET 10.0 | PreloadedKey | 63.20 μs / 121.48 KB | 42.62 μs / 9.73 KB | -32.6% | -92.0% |

- Validation takes 25% to 33% less time. Each operation allocates 76% to 92% less memory.
- Load the key once. A preloaded key decreases the build time from about 47 μs to about 24 μs.
- `ValidateTokenAsync` with a key resolver takes about 1.2 μs more than `TryValidateToken`.
- Version 8.0.1058 adds the `exp`, `nbf` and format checks. Its results differ from 8.0.973 by -1% to +3%.
