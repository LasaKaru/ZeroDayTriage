using ZeroDayTriage.Core.Abstractions;

namespace ZeroDayTriage.Tools.Collection;

/// <summary>
/// Shared plumbing for tool runners: applies the launcher prefix and command overrides, runs the
/// subprocess, captures stdout+stderr (many of these tools log to stderr), and normalizes the
/// real output into findings — never throwing, so one missing binary can't sink a collection run.
/// </summary>
public abstract class ToolRunnerBase : IToolRunner
{
    public abstract string Name { get; }

    /// <summary>The default executable name when no override is supplied.</summary>
    protected abstract string DefaultCommand { get; }

    protected abstract INormalizer Normalizer { get; }

    public abstract bool IsApplicable(TargetContext context);

    /// <summary>The tool-specific arguments (everything after the executable name).</summary>
    protected abstract IReadOnlyList<string> BuildToolArguments(TargetContext context);

    public (string FileName, IReadOnlyList<string> Arguments) BuildCommand(TargetContext context, ToolSettings settings)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(settings);

        var command = settings.CommandOverrides.TryGetValue(Name, out var overridden)
            ? overridden
            : DefaultCommand;

        var toolArgs = BuildToolArguments(context);

        if (!string.IsNullOrWhiteSpace(settings.LauncherPrefix))
        {
            // e.g. wsl nxc smb 10.0.0.5 -u a -p b
            var launcherParts = settings.LauncherPrefix.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var args = new List<string>(launcherParts.Skip(1)) { command };
            args.AddRange(toolArgs);
            return (launcherParts[0], args);
        }

        return (command, toolArgs);
    }

    public async Task<ToolRunResult> RunAsync(
        TargetContext context,
        ToolSettings settings,
        IProcessRunner processRunner,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(processRunner);

        var (fileName, arguments) = BuildCommand(context, settings);
        var rendered = $"{fileName} {string.Join(' ', arguments)}";

        if (settings.DryRun)
        {
            return new ToolRunResult(Name, Executed: false, rendered, RawOutput: string.Empty,
                Array.Empty<Core.Model.Finding>(), Error: "dry-run (not executed)");
        }

        try
        {
            var result = await processRunner
                .RunAsync(fileName, arguments, timeout: settings.Timeout, cancellationToken: cancellationToken)
                .ConfigureAwait(false);

            // Combine streams: nxc/certipy frequently emit their useful output on stderr.
            var raw = string.Concat(result.StandardOutput, "\n", result.StandardError);
            var findings = SafeParse(raw);

            string? error = null;
            if (result.TimedOut)
            {
                error = $"timed out after {settings.Timeout}";
            }
            else if (!result.Succeeded && findings.Count == 0)
            {
                error = $"exit code {result.ExitCode}";
            }

            return new ToolRunResult(Name, Executed: true, rendered, raw, findings, error);
        }
        catch (Exception ex)
        {
            // Binary not found, WSL missing, permission denied, etc. — report, don't crash.
            return new ToolRunResult(Name, Executed: false, rendered, RawOutput: string.Empty,
                Array.Empty<Core.Model.Finding>(), Error: ex.Message);
        }
    }

    private IReadOnlyList<Core.Model.Finding> SafeParse(string raw)
    {
        try
        {
            return Normalizer.CanParse(raw) ? Normalizer.Parse(raw) : Array.Empty<Core.Model.Finding>();
        }
        catch
        {
            return Array.Empty<Core.Model.Finding>();
        }
    }
}
