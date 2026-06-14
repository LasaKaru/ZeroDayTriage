using ZeroDayTriage.Core.Model;

namespace ZeroDayTriage.Reasoning.Tests;

/// <summary>Fluent test-data builders so rule tests read like the scenario they describe.</summary>
internal static class Builders
{
    public static Finding Finding(
        string title,
        string? principal = null,
        AssetDomain domain = AssetDomain.ActiveDirectory,
        Severity severity = Severity.High,
        Confidence confidence = Confidence.Confirmed,
        string source = "test",
        string? technique = null,
        IDictionary<string, string>? properties = null,
        params string[] tags) => new Finding
        {
            Title = title,
            Principal = principal,
            Domain = domain,
            Severity = severity,
            Confidence = confidence,
            Source = source,
            Technique = technique,
            Tags = tags,
            Properties = properties is null
                ? new Dictionary<string, string>()
                : new Dictionary<string, string>(properties),
        }.WithComputedId();

    public static FindingCorpus Corpus(params Finding[] findings) => new(findings);

    public static Finding Kerberoastable(string principal) =>
        Finding($"Kerberoastable: {principal}", principal, technique: "T1558.003", tags: new[] { "kerberoastable" });

    public static Finding GenericWrite(string holder, string target) =>
        Finding($"GenericWrite over {target}", holder, technique: "T1222",
            properties: new Dictionary<string, string> { ["target"] = target, ["right"] = "GenericWrite" },
            tags: new[] { "genericwrite" });
}
