using ZeroDayTriage.Core.Model;

namespace ZeroDayTriage.Core.Abstractions;

/// <summary>
/// The live target an operator is engaging: where it is, and what credentials we already hold.
/// Tool runners read this to build their command lines.
/// </summary>
public sealed record TargetContext
{
    /// <summary>Host, IP, hostname, or CIDR the tools point at.</summary>
    public required string Target { get; init; }

    public string? Domain { get; init; }

    public string? Username { get; init; }

    public string? Password { get; init; }

    /// <summary>NTLM hash for pass-the-hash style authentication (LM:NT or bare NT).</summary>
    public string? NtlmHash { get; init; }

    /// <summary>Domain controller IP, required by tools like Certipy and GetUserSPNs.</summary>
    public string? DcIp { get; init; }

    public bool HasCredentials =>
        !string.IsNullOrWhiteSpace(Username) &&
        (!string.IsNullOrWhiteSpace(Password) || !string.IsNullOrWhiteSpace(NtlmHash));
}

/// <summary>
/// How the orchestrator should invoke tools. This is what makes the runner work in the real
/// world: tools usually live in WSL/Kali, under different names, with operator-specific flags.
/// </summary>
public sealed record ToolSettings
{
    /// <summary>
    /// Optional launcher prepended to every command — e.g. "wsl" so a Windows host runs the
    /// Linux tooling as <c>wsl nxc smb ...</c>. Null runs the tool binary directly.
    /// </summary>
    public string? LauncherPrefix { get; init; }

    /// <summary>Per-tool command/path overrides keyed by runner name (e.g. "netexec" -&gt; "crackmapexec").</summary>
    public IReadOnlyDictionary<string, string> CommandOverrides { get; init; }
        = new Dictionary<string, string>();

    public TimeSpan Timeout { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>When true, the planned command is reported but never executed.</summary>
    public bool DryRun { get; init; }
}

/// <summary>The outcome of running one tool against a target.</summary>
public sealed record ToolRunResult(
    string Tool,
    bool Executed,
    string Command,
    string RawOutput,
    IReadOnlyList<Finding> Findings,
    string? Error)
{
    public bool Succeeded => Executed && Error is null;
}

/// <summary>
/// Executes one proven tool against a <see cref="TargetContext"/> and normalizes its real output
/// into findings. This is the orchestration layer the strategy plan calls for: run battle-tested
/// tools, collect their output, hand it to the reasoning engine.
/// </summary>
public interface IToolRunner
{
    string Name { get; }

    /// <summary>Whether this runner has what it needs to run against the target (e.g. credentials).</summary>
    bool IsApplicable(TargetContext context);

    /// <summary>The exact command that would run — used for dry-runs and the operator audit trail.</summary>
    (string FileName, IReadOnlyList<string> Arguments) BuildCommand(TargetContext context, ToolSettings settings);

    Task<ToolRunResult> RunAsync(
        TargetContext context,
        ToolSettings settings,
        IProcessRunner processRunner,
        CancellationToken cancellationToken = default);
}
