# Utilities.Jwt.Ed25519

[![GitHub](https://img.shields.io/github/license/ed555009/utilities-jwt-ed25519)](LICENSE)
![Build Status](https://dev.azure.com/edwang/github/_apis/build/status/utilities-jwt-ed25519?branchName=main)
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

```
BenchmarkDotNet v0.14.0, macOS Sonoma 14.3 (23D56) [Darwin 23.3.0]
Apple M3 Pro, 1 CPU, 11 logical and 11 physical cores
.NET SDK 8.0.302
  [Host]     : .NET 8.0.6 (8.0.624.26715), Arm64 RyuJIT AdvSIMD
  DefaultJob : .NET 8.0.6 (8.0.624.26715), Arm64 RyuJIT AdvSIMD
```
| Method                         | Mean     | Error    | StdDev   | Allocated |
|------------------------------- |---------:|---------:|---------:|----------:|
| BuildTokenWithCustomPayload    | 52.34 μs | 1.018 μs | 1.288 μs |  68.09 KB |
| ValidateTokenWithCustomPayload | 69.20 μs | 1.382 μs | 2.760 μs | 133.68 KB |
