using BenchmarkDotNet.Running;
using Utilities.Jwt.Ed25519.Benchmarks;

// Run: dotnet run -c Release -f net10.0 -- --filter '*' --runtimes net8.0 net10.0
_ = BenchmarkSwitcher.FromAssembly(typeof(JwtBenchmarks).Assembly).Run(args);
