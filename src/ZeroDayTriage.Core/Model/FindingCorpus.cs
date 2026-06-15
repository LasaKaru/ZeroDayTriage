namespace ZeroDayTriage.Core.Model;

/// <summary>
/// An immutable, pre-indexed view over a set of findings. Attack-path rules query this
/// rather than scanning a flat list, so correlation across principals and tags stays
/// O(1)-ish instead of O(n) per lookup.
/// </summary>
public sealed class FindingCorpus
{
    private readonly IReadOnlyList<Finding> _all;
    private readonly ILookup<string, Finding> _byTag;
    private readonly ILookup<string, Finding> _byPrincipal;
    private readonly ILookup<AssetDomain, Finding> _byDomain;
    private readonly IReadOnlyDictionary<string, Finding> _byId;

    public FindingCorpus(IEnumerable<Finding> findings)
    {
        ArgumentNullException.ThrowIfNull(findings);
        _all = findings.ToList();

        _byTag = _all
            .SelectMany(f => f.Tags.Select(t => (Tag: t.ToLowerInvariant(), Finding: f)))
            .ToLookup(x => x.Tag, x => x.Finding);

        _byPrincipal = _all
            .Where(f => !string.IsNullOrWhiteSpace(f.Principal))
            .ToLookup(f => Normalize(f.Principal!), f => f);

        _byDomain = _all.ToLookup(f => f.Domain);

        _byId = _all
            .Where(f => !string.IsNullOrEmpty(f.Id))
            .GroupBy(f => f.Id)
            .ToDictionary(g => g.Key, g => g.First());
    }

    public IReadOnlyList<Finding> All => _all;

    public int Count => _all.Count;

    public IEnumerable<Finding> WithTag(string tag) => _byTag[tag.ToLowerInvariant()];

    public bool HasTag(string tag) => _byTag.Contains(tag.ToLowerInvariant());

    public IEnumerable<Finding> ForPrincipal(string principal) =>
        string.IsNullOrWhiteSpace(principal)
            ? Enumerable.Empty<Finding>()
            : _byPrincipal[Normalize(principal)];

    public IEnumerable<Finding> InDomain(AssetDomain domain) => _byDomain[domain];

    public Finding? ById(string id) => _byId.TryGetValue(id, out var f) ? f : null;

    /// <summary>
    /// Normalizes a principal name for matching: case-insensitive and DOMAIN\user or
    /// user@domain forms collapse to the bare sAMAccountName-ish token.
    /// </summary>
    public static string Normalize(string principal)
    {
        var p = principal.Trim().ToLowerInvariant();
        var slash = p.LastIndexOf('\\');
        if (slash >= 0 && slash < p.Length - 1)
        {
            p = p[(slash + 1)..];
        }

        var at = p.IndexOf('@');
        if (at > 0)
        {
            p = p[..at];
        }

        return p;
    }
}
