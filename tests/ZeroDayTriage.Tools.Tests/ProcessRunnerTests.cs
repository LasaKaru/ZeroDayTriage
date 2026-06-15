using System.Runtime.InteropServices;
using FluentAssertions;
using ZeroDayTriage.Tools.Execution;
using Xunit;

namespace ZeroDayTriage.Tools.Tests;

/// <summary>
/// Exercises the real subprocess runner against POSIX shell utilities. Skipped on non-Unix
/// hosts where the referenced binaries are absent.
/// </summary>
public sealed class ProcessRunnerTests
{
    private static bool Unix => !RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

    private readonly ProcessRunner _sut = new();

    [SkippableFact]
    public async Task Captures_stdout_and_zero_exit()
    {
        Skip.IfNot(Unix);

        var result = await _sut.RunAsync("/bin/echo", new[] { "evilcorp" });

        result.Succeeded.Should().BeTrue();
        result.ExitCode.Should().Be(0);
        result.StandardOutput.Trim().Should().Be("evilcorp");
        result.TimedOut.Should().BeFalse();
    }

    [SkippableFact]
    public async Task Surfaces_non_zero_exit_code()
    {
        Skip.IfNot(Unix);

        var result = await _sut.RunAsync("/bin/sh", new[] { "-c", "exit 3" });

        result.Succeeded.Should().BeFalse();
        result.ExitCode.Should().Be(3);
    }

    [SkippableFact]
    public async Task Captures_stderr()
    {
        Skip.IfNot(Unix);

        var result = await _sut.RunAsync("/bin/sh", new[] { "-c", "echo boom 1>&2" });

        result.StandardError.Trim().Should().Be("boom");
    }

    [SkippableFact]
    public async Task Enforces_timeout_and_flags_timed_out()
    {
        Skip.IfNot(Unix);

        var result = await _sut.RunAsync(
            "/bin/sleep",
            new[] { "10" },
            timeout: TimeSpan.FromMilliseconds(250));

        result.TimedOut.Should().BeTrue();
        result.Succeeded.Should().BeFalse();
        result.Duration.Should().BeLessThan(TimeSpan.FromSeconds(5));
    }

    [SkippableFact]
    public async Task Honors_external_cancellation()
    {
        Skip.IfNot(Unix);

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));

        var act = async () => await _sut.RunAsync(
            "/bin/sleep",
            new[] { "10" },
            cancellationToken: cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task Rejects_empty_filename()
    {
        var act = async () => await _sut.RunAsync(" ", Array.Empty<string>());
        await act.Should().ThrowAsync<ArgumentException>();
    }
}
