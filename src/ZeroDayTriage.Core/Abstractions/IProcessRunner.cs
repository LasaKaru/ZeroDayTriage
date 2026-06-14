namespace ZeroDayTriage.Core.Abstractions;

/// <summary>The captured result of running an external tool as a subprocess.</summary>
public sealed record ProcessResult(
    string FileName,
    int ExitCode,
    string StandardOutput,
    string StandardError,
    TimeSpan Duration,
    bool TimedOut)
{
    public bool Succeeded => !TimedOut && ExitCode == 0;
}

/// <summary>
/// Abstraction over subprocess execution. Tool runners depend on this rather than
/// <see cref="System.Diagnostics.Process"/> directly so they are unit-testable without
/// the proven tools (SharpHound, nxc, Certipy ...) installed on the test host.
/// </summary>
public interface IProcessRunner
{
    Task<ProcessResult> RunAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        string? workingDirectory = null,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default);
}
