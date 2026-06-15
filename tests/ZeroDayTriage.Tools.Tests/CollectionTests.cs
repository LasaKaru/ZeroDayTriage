using FluentAssertions;
using NSubstitute;
using ZeroDayTriage.Core.Abstractions;
using ZeroDayTriage.Tools.Collection;
using Xunit;

namespace ZeroDayTriage.Tools.Tests;

public sealed class NetExecRunnerTests
{
    private readonly NetExecRunner _sut = new();
    private static readonly ToolSettings Default = new();

    [Fact]
    public void BuildCommand_uses_password_authentication()
    {
        var ctx = new TargetContext { Target = "10.0.0.5", Domain = "evilcorp.local", Username = "jdoe", Password = "p" };

        var (file, args) = _sut.BuildCommand(ctx, Default);

        file.Should().Be("nxc");
        args.Should().ContainInOrder("smb", "10.0.0.5", "-d", "evilcorp.local", "-u", "jdoe", "-p", "p");
    }

    [Fact]
    public void BuildCommand_uses_hash_for_pass_the_hash()
    {
        var ctx = new TargetContext { Target = "10.0.0.5", Username = "jdoe", NtlmHash = "aad3b...:5f4d..." };

        var (_, args) = _sut.BuildCommand(ctx, Default);

        args.Should().Contain("-H").And.Contain("aad3b...:5f4d...");
        args.Should().NotContain("-p");
    }

    [Fact]
    public void BuildCommand_applies_launcher_prefix()
    {
        var ctx = new TargetContext { Target = "10.0.0.5", Username = "jdoe", Password = "p" };

        var (file, args) = _sut.BuildCommand(ctx, new ToolSettings { LauncherPrefix = "wsl" });

        file.Should().Be("wsl");
        args[0].Should().Be("nxc");
    }

    [Fact]
    public void BuildCommand_honors_command_override()
    {
        var ctx = new TargetContext { Target = "10.0.0.5", Username = "jdoe", Password = "p" };

        var (file, _) = _sut.BuildCommand(ctx, new ToolSettings
        {
            CommandOverrides = new Dictionary<string, string> { ["netexec"] = "crackmapexec" },
        });

        file.Should().Be("crackmapexec");
    }

    [Theory]
    [InlineData(null, null, false)]   // no creds
    [InlineData("jdoe", null, false)] // user but no secret
    [InlineData("jdoe", "p", true)]   // full creds
    public void IsApplicable_requires_credentials(string? user, string? pass, bool expected)
    {
        var ctx = new TargetContext { Target = "10.0.0.5", Username = user, Password = pass };

        _sut.IsApplicable(ctx).Should().Be(expected);
    }

    [Fact]
    public async Task RunAsync_parses_real_process_output_into_findings()
    {
        var ctx = new TargetContext { Target = "10.0.0.7", Username = "jdoe", Password = "p" };
        var processRunner = Substitute.For<IProcessRunner>();
        processRunner
            .RunAsync(Arg.Any<string>(), Arg.Any<IReadOnlyList<string>>(), Arg.Any<string?>(),
                Arg.Any<TimeSpan?>(), Arg.Any<CancellationToken>())
            .Returns(new ProcessResult("nxc", 0,
                "SMB 10.0.0.7 445 FS01 [+] evilcorp.local\\backupadmin:aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99 (Pwn3d!)",
                string.Empty, TimeSpan.Zero, false));

        var result = await _sut.RunAsync(ctx, Default, processRunner);

        result.Executed.Should().BeTrue();
        result.Findings.Should().Contain(f => f.HasTag("pass-the-hash"));
    }

    [Fact]
    public async Task RunAsync_dry_run_does_not_execute()
    {
        var ctx = new TargetContext { Target = "10.0.0.7", Username = "jdoe", Password = "p" };
        var processRunner = Substitute.For<IProcessRunner>();

        var result = await _sut.RunAsync(ctx, new ToolSettings { DryRun = true }, processRunner);

        result.Executed.Should().BeFalse();
        result.Command.Should().Contain("nxc");
        await processRunner.DidNotReceive().RunAsync(
            Arg.Any<string>(), Arg.Any<IReadOnlyList<string>>(), Arg.Any<string?>(),
            Arg.Any<TimeSpan?>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task RunAsync_reports_a_missing_binary_without_throwing()
    {
        var ctx = new TargetContext { Target = "10.0.0.7", Username = "jdoe", Password = "p" };
        var processRunner = Substitute.For<IProcessRunner>();
        processRunner
            .RunAsync(Arg.Any<string>(), Arg.Any<IReadOnlyList<string>>(), Arg.Any<string?>(),
                Arg.Any<TimeSpan?>(), Arg.Any<CancellationToken>())
            .Returns<ProcessResult>(_ => throw new System.ComponentModel.Win32Exception("No such file or directory"));

        var result = await _sut.RunAsync(ctx, Default, processRunner);

        result.Executed.Should().BeFalse();
        result.Error.Should().Contain("No such file");
    }
}

public sealed class CertipyRunnerTests
{
    private readonly CertipyRunner _sut = new();

    [Fact]
    public void IsApplicable_requires_credentials_and_dc_ip()
    {
        _sut.IsApplicable(new TargetContext { Target = "x", Username = "u", Password = "p" }).Should().BeFalse();
        _sut.IsApplicable(new TargetContext { Target = "x", Username = "u", Password = "p", DcIp = "10.0.0.5" }).Should().BeTrue();
    }

    [Fact]
    public void BuildCommand_targets_adcs_with_upn_and_json_output()
    {
        var ctx = new TargetContext { Target = "x", Domain = "evilcorp.local", Username = "jdoe", Password = "p", DcIp = "10.0.0.5" };

        var (file, args) = _sut.BuildCommand(ctx, new ToolSettings());

        file.Should().Be("certipy");
        args.Should().ContainInOrder("find", "-u", "jdoe@evilcorp.local");
        args.Should().Contain("-vulnerable").And.Contain("-json").And.Contain("-dc-ip");
    }
}

public sealed class ToolOrchestratorTests
{
    [Fact]
    public async Task CollectAsync_skips_inapplicable_runners_with_a_reason()
    {
        var processRunner = Substitute.For<IProcessRunner>();
        var orchestrator = ToolOrchestrator.CreateDefault(processRunner);
        // No DC IP -> certipy is skipped; no creds -> netexec is skipped too.
        var ctx = new TargetContext { Target = "10.0.0.5" };

        var results = await orchestrator.CollectAsync(ctx, new ToolSettings());

        results.Should().OnlyContain(r => !r.Executed);
        results.Should().Contain(r => r.Tool == "certipy" && r.Error!.Contains("dc-ip"));
    }

    [Fact]
    public async Task CollectAsync_runs_applicable_runners()
    {
        var processRunner = Substitute.For<IProcessRunner>();
        processRunner
            .RunAsync(Arg.Any<string>(), Arg.Any<IReadOnlyList<string>>(), Arg.Any<string?>(),
                Arg.Any<TimeSpan?>(), Arg.Any<CancellationToken>())
            .Returns(new ProcessResult("nxc", 0,
                "SMB 10.0.0.5 445 DC01 [+] evilcorp.local\\svc:pw", string.Empty, TimeSpan.Zero, false));

        var orchestrator = ToolOrchestrator.CreateDefault(processRunner);
        var ctx = new TargetContext { Target = "10.0.0.5", Username = "svc", Password = "pw" };

        var results = await orchestrator.CollectAsync(ctx, new ToolSettings());

        results.Should().Contain(r => r.Tool == "netexec" && r.Executed);
        ToolOrchestrator.AllFindings(results).Should().NotBeEmpty();
    }
}
