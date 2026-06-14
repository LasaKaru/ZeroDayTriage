using System.Diagnostics;
using System.Text;
using ZeroDayTriage.Core.Abstractions;

namespace ZeroDayTriage.Tools.Execution;

/// <summary>
/// Default <see cref="IProcessRunner"/> backed by <see cref="Process"/>. Streams stdout and
/// stderr concurrently to avoid pipe-buffer deadlocks, enforces a wall-clock timeout, and
/// kills the whole process tree on cancellation or timeout.
/// </summary>
public sealed class ProcessRunner : IProcessRunner
{
    private readonly TimeSpan _defaultTimeout;

    public ProcessRunner(TimeSpan? defaultTimeout = null)
    {
        _defaultTimeout = defaultTimeout ?? TimeSpan.FromMinutes(10);
    }

    public async Task<ProcessResult> RunAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        string? workingDirectory = null,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fileName);
        ArgumentNullException.ThrowIfNull(arguments);

        var effectiveTimeout = timeout ?? _defaultTimeout;
        var startInfo = new ProcessStartInfo
        {
            FileName = fileName,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = workingDirectory ?? Environment.CurrentDirectory,
        };

        foreach (var arg in arguments)
        {
            startInfo.ArgumentList.Add(arg);
        }

        using var process = new Process { StartInfo = startInfo };
        var stdout = new StringBuilder();
        var stderr = new StringBuilder();

        process.OutputDataReceived += (_, e) =>
        {
            if (e.Data is not null)
            {
                lock (stdout)
                {
                    stdout.AppendLine(e.Data);
                }
            }
        };
        process.ErrorDataReceived += (_, e) =>
        {
            if (e.Data is not null)
            {
                lock (stderr)
                {
                    stderr.AppendLine(e.Data);
                }
            }
        };

        var stopwatch = Stopwatch.StartNew();
        if (!process.Start())
        {
            throw new InvalidOperationException($"Failed to start process '{fileName}'.");
        }

        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(effectiveTimeout);

        var timedOut = false;
        try
        {
            await process.WaitForExitAsync(timeoutCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            timedOut = !cancellationToken.IsCancellationRequested;
            TryKill(process);
            if (cancellationToken.IsCancellationRequested)
            {
                stopwatch.Stop();
                throw;
            }
        }

        stopwatch.Stop();

        // Ensure async readers have drained before we read the buffers.
        if (!timedOut)
        {
            process.WaitForExit();
        }

        var exitCode = timedOut ? -1 : SafeExitCode(process);

        return new ProcessResult(
            fileName,
            exitCode,
            stdout.ToString(),
            stderr.ToString(),
            stopwatch.Elapsed,
            timedOut);
    }

    private static int SafeExitCode(Process process)
    {
        try
        {
            return process.ExitCode;
        }
        catch (InvalidOperationException)
        {
            return -1;
        }
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or NotSupportedException)
        {
            // Process already gone or platform refused the tree kill; nothing else to do.
        }
    }
}
