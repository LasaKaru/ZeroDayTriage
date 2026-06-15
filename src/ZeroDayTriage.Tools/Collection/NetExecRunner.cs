using ZeroDayTriage.Core.Abstractions;
using ZeroDayTriage.Tools.Normalizers;

namespace ZeroDayTriage.Tools.Collection;

/// <summary>
/// Runs NetExec (nxc) SMB authentication/enumeration against the target and normalizes the real
/// console output. Supports both password and pass-the-hash authentication.
/// </summary>
public sealed class NetExecRunner : ToolRunnerBase
{
    public override string Name => "netexec";

    protected override string DefaultCommand => "nxc";

    protected override INormalizer Normalizer { get; } = new NetExecNormalizer();

    public override bool IsApplicable(TargetContext context) =>
        !string.IsNullOrWhiteSpace(context.Target) && context.HasCredentials;

    protected override IReadOnlyList<string> BuildToolArguments(TargetContext context)
    {
        var args = new List<string> { "smb", context.Target };

        if (!string.IsNullOrWhiteSpace(context.Domain))
        {
            args.Add("-d");
            args.Add(context.Domain);
        }

        args.Add("-u");
        args.Add(context.Username!);

        if (!string.IsNullOrWhiteSpace(context.NtlmHash))
        {
            args.Add("-H");
            args.Add(context.NtlmHash);
        }
        else
        {
            args.Add("-p");
            args.Add(context.Password!);
        }

        return args;
    }
}
