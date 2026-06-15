using ZeroDayTriage.Core.Abstractions;
using ZeroDayTriage.Core.Model;

namespace ZeroDayTriage.Tools.Collection;

/// <summary>
/// Runs every applicable tool runner against a target and aggregates the real findings. This is
/// the live counterpart to <c>ingest</c>: instead of reading saved tool dumps, it executes the
/// tools itself.
/// </summary>
public sealed class ToolOrchestrator
{
    private readonly IReadOnlyList<IToolRunner> _runners;
    private readonly IProcessRunner _processRunner;

    public ToolOrchestrator(IEnumerable<IToolRunner> runners, IProcessRunner processRunner)
    {
        ArgumentNullException.ThrowIfNull(runners);
        ArgumentNullException.ThrowIfNull(processRunner);
        _runners = runners.ToList();
        _processRunner = processRunner;
    }

    /// <summary>Orchestrator wired with the built-in live runners (NetExec, Certipy).</summary>
    public static ToolOrchestrator CreateDefault(IProcessRunner processRunner) =>
        new(new IToolRunner[] { new NetExecRunner(), new CertipyRunner() }, processRunner);

    public IReadOnlyList<IToolRunner> Runners => _runners;

    /// <summary>
    /// Runs all applicable runners. Returns one <see cref="ToolRunResult"/> per attempted tool so
    /// the caller can report exactly what ran, what failed, and what was collected.
    /// </summary>
    public async Task<IReadOnlyList<ToolRunResult>> CollectAsync(
        TargetContext context,
        ToolSettings settings,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(settings);

        var results = new List<ToolRunResult>();
        foreach (var runner in _runners)
        {
            if (!runner.IsApplicable(context))
            {
                results.Add(new ToolRunResult(runner.Name, Executed: false, Command: string.Empty,
                    RawOutput: string.Empty, Array.Empty<Finding>(),
                    Error: "skipped (insufficient context — needs credentials" +
                           (runner.Name == "certipy" ? " and --dc-ip)" : ")")));
                continue;
            }

            results.Add(await runner.RunAsync(context, settings, _processRunner, cancellationToken)
                .ConfigureAwait(false));
        }

        return results;
    }

    /// <summary>Flattens all findings collected across the runners.</summary>
    public static IReadOnlyList<Finding> AllFindings(IEnumerable<ToolRunResult> results) =>
        results.SelectMany(r => r.Findings).ToList();
}
