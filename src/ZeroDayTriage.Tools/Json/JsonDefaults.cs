using System.Text.Json;
using System.Text.Json.Serialization;

namespace ZeroDayTriage.Tools.Json;

/// <summary>Shared, case-insensitive JSON options used across normalizers and exporters.</summary>
public static class JsonDefaults
{
    public static readonly JsonSerializerOptions Options = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };
}
