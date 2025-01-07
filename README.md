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
| **Algorithm**         | Edwards-curve Digital Signature Algorithm (ECDSA) | RSA (asymmetric encryption)    |
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
## Using service

### Build token

```csharp
using Utilities.Jwt.Ed25519.Enums;
using Utilities.Jwt.Ed25519.Models;
using Utilities.Jwt.Ed25519.Services;

// private key
private readonly string _privateKey = @"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIBjirw/3PNIj5F6kfA100R6k2s9Wgb7yxYrVZbDfnOJf
-----END PRIVATE KEY-----
";

// prepare payload
var now = DateTimeOffset.UtcNow;
var payload = new JwtPayload
{
	Subject = "Subject",
	Issuer = "Issuer",
	Audience = "Audience",
	Expiration = now.AddMinutes(1).ToUnixTimeSeconds(),
	IssuedAt = now.ToUnixTimeSeconds(),
	NotBefore = now.ToUnixTimeSeconds(),
	JwtId = Guid.NewGuid().ToString()
};

// add custom claims (any type)
payload.AddClaim("stringClaim", "claimValue");
payload.AddClaim("numericClaim", 12345);

// load private key from string
var privateKey = JwtService.LoadPrivateKey(_privateKey);

// or, load private key from file
var privateKey = JwtService.LoadPrivateKey("path/to/private.pem", LoadKeyType.File);

// build token
var token = JwtService.BuildToken(payload, privateKey);
```

### Validate token

```csharp
using Utilities.Jwt.Ed25519.Enums;
using Utilities.Jwt.Ed25519.Models;
using Utilities.Jwt.Ed25519.Services;

// public key
private readonly string _publicKey = @"-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAFYcbSrDaJytx/y7qxFZQpUGb+GORxSBWY2PrOo5fnIY=
-----END PUBLIC KEY-----
";

// load public key from string
var publicKey = JwtService.LoadPublicKey(_publicKey);

// or, load public key from file
var publicKey = JwtService.LoadPublicKey("path/to/public.pem", LoadKeyType.File);

// validate token
var isValid = JwtService.ValidateToken(token, publicKey, out var payload);
```

**Note:** `payload` is `Dictionary<string, object>?` type, `ValidateToken()` only validates the token `signature` and `algorithm`, it does not validate the token claims. You can validate the claims manually by checking the payload values.

### Custom payload class

You can use your custom payload class by inheriting the `BaseJwtPayload` class.

```csharp
using System.Text.Json.Serialization;

public class MyCustomPayload : BaseJwtPayload
{
	[JsonPropertyName("custom_claim")]
	public string? CustomClaim { get; set; }
}
```

Then, use the custom payload class with the `JwtService`.

```csharp
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
```

Finally, build and validate the token.

```csharp
// build token
var token = JwtService.BuildToken<MyCustomPayload>(payload, privateKey);

// validate token
var isValid = JwtService.ValidateToken<MyCustomPayload>(token, publicKey, out var payload);
```

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
| BuildToken                     | 50.59 μs | 1.006 μs | 0.988 μs |  69.23 KB |
| BuildTokenWithCustomPayload    | 52.34 μs | 1.018 μs | 1.288 μs |  68.09 KB |
| ValidateToken                  | 69.59 μs | 1.359 μs | 2.270 μs | 136.41 KB |
| ValidateTokenWithCustomPayload | 69.20 μs | 1.382 μs | 2.760 μs | 133.68 KB |
