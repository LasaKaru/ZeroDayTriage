namespace ZeroDayTriage.Cli;

/// <summary>
/// Minimal, dependency-free parser for <c>--key value</c> / <c>--flag</c> arguments. Kept
/// deliberately small so the CLI has no preview NuGet dependencies and stays offline-safe.
/// </summary>
public sealed class ArgMap
{
    private readonly Dictionary<string, string?> _values = new(StringComparer.OrdinalIgnoreCase);

    public ArgMap(IEnumerable<string> args)
    {
        var list = args.ToList();
        for (var i = 0; i < list.Count; i++)
        {
            var token = list[i];
            if (!token.StartsWith("--", StringComparison.Ordinal))
            {
                continue;
            }

            var key = token[2..];
            if (i + 1 < list.Count && !list[i + 1].StartsWith("--", StringComparison.Ordinal))
            {
                _values[key] = list[i + 1];
                i++;
            }
            else
            {
                _values[key] = null; // bare flag
            }
        }
    }

    public bool Has(string key) => _values.ContainsKey(key);

    public string? Get(string key, string? fallback = null) =>
        _values.TryGetValue(key, out var value) && value is not null ? value : fallback;

    public int GetInt(string key, int fallback)
    {
        var raw = Get(key);
        return int.TryParse(raw, out var value) ? value : fallback;
    }
}
