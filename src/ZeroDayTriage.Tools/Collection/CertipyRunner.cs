using ZeroDayTriage.Core.Abstractions;
using ZeroDayTriage.Tools.Normalizers;

namespace ZeroDayTriage.Tools.Collection;

/// <summary>
/// Runs Certipy's <c>find</c> against AD CS and normalizes the vulnerable-template output.
/// Uses <c>-stdout -json</c> so the JSON report comes back on the pipe rather than a timestamped
/// file. (Certipy's exact flags vary by version; override with --certipy-command / a raw run if
/// your build differs.)
/// </summary>
public sealed class CertipyRunner : ToolRunnerBase
{
    public override string Name => "certipy";

    protected override string DefaultCommand => "certipy";

    protected override INormalizer Normalizer { get; } = new CertipyNormalizer();

    public override bool IsApplicable(TargetContext context) =>
        context.HasCredentials && !string.IsNullOrWhiteSpace(context.DcIp);

    protected override IReadOnlyList<string> BuildToolArguments(TargetContext context)
    {
        var upn = string.IsNullOrWhiteSpace(context.Domain)
            ? context.Username!
            : $"{context.Username}@{context.Domain}";

        var args = new List<string> { "find", "-u", upn };

        if (!string.IsNullOrWhiteSpace(context.NtlmHash))
        {
            args.Add("-hashes");
            args.Add(context.NtlmHash);
        }
        else
        {
            args.Add("-p");
            args.Add(context.Password!);
        }

        args.Add("-dc-ip");
        args.Add(context.DcIp!);
        args.Add("-vulnerable");
        args.Add("-stdout");
        args.Add("-json");

        return args;
    }
}
