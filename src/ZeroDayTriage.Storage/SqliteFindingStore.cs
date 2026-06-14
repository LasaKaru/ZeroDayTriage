using System.Text.Json;
using Microsoft.Data.Sqlite;
using ZeroDayTriage.Core.Abstractions;
using ZeroDayTriage.Core.Model;

namespace ZeroDayTriage.Storage;

/// <summary>
/// SQLite-backed <see cref="IFindingStore"/>. Findings are keyed by their content
/// fingerprint so re-ingesting the same tool output is idempotent. Complex fields
/// (properties, tags) are persisted as JSON columns.
/// </summary>
public sealed class SqliteFindingStore : IFindingStore
{
    private static readonly JsonSerializerOptions JsonOptions = new();

    private readonly string _connectionString;

    public SqliteFindingStore(string connectionString)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        _connectionString = connectionString;
    }

    /// <summary>Creates a store backed by a database file at <paramref name="path"/>.</summary>
    public static SqliteFindingStore ForFile(string path)
    {
        var builder = new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
        };
        return new SqliteFindingStore(builder.ToString());
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText =
            """
            CREATE TABLE IF NOT EXISTS findings (
                id            TEXT PRIMARY KEY,
                title         TEXT NOT NULL,
                domain        TEXT NOT NULL,
                severity      INTEGER NOT NULL,
                confidence    INTEGER NOT NULL,
                source        TEXT NOT NULL,
                principal     TEXT NULL,
                technique     TEXT NULL,
                properties    TEXT NOT NULL,
                tags          TEXT NOT NULL,
                evidence      TEXT NULL,
                discovered_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_findings_domain ON findings(domain);
            CREATE INDEX IF NOT EXISTS ix_findings_principal ON findings(principal);
            """;
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<int> UpsertAsync(IEnumerable<Finding> findings, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(findings);

        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        var before = await CountAsync(connection, cancellationToken).ConfigureAwait(false);

        await using var transaction = (SqliteTransaction)await connection
            .BeginTransactionAsync(cancellationToken).ConfigureAwait(false);

        foreach (var raw in findings)
        {
            var finding = string.IsNullOrEmpty(raw.Id) ? raw.WithComputedId() : raw;

            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText =
                """
                INSERT INTO findings
                    (id, title, domain, severity, confidence, source, principal, technique, properties, tags, evidence, discovered_at)
                VALUES
                    ($id, $title, $domain, $severity, $confidence, $source, $principal, $technique, $properties, $tags, $evidence, $discovered)
                ON CONFLICT(id) DO UPDATE SET
                    severity   = MAX(severity, excluded.severity),
                    confidence = MAX(confidence, excluded.confidence),
                    evidence   = COALESCE(excluded.evidence, evidence);
                """;

            command.Parameters.AddWithValue("$id", finding.Id);
            command.Parameters.AddWithValue("$title", finding.Title);
            command.Parameters.AddWithValue("$domain", finding.Domain.ToString());
            command.Parameters.AddWithValue("$severity", (int)finding.Severity);
            command.Parameters.AddWithValue("$confidence", (int)finding.Confidence);
            command.Parameters.AddWithValue("$source", finding.Source);
            command.Parameters.AddWithValue("$principal", (object?)finding.Principal ?? DBNull.Value);
            command.Parameters.AddWithValue("$technique", (object?)finding.Technique ?? DBNull.Value);
            command.Parameters.AddWithValue("$properties", JsonSerializer.Serialize(finding.Properties, JsonOptions));
            command.Parameters.AddWithValue("$tags", JsonSerializer.Serialize(finding.Tags, JsonOptions));
            command.Parameters.AddWithValue("$evidence", (object?)finding.Evidence ?? DBNull.Value);
            command.Parameters.AddWithValue("$discovered", finding.DiscoveredAt.ToString("O"));

            await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }

        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);

        var after = await CountAsync(connection, cancellationToken).ConfigureAwait(false);
        return after - before;
    }

    public async Task<IReadOnlyList<Finding>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT id, title, domain, severity, confidence, source, principal, technique, properties, tags, evidence, discovered_at FROM findings;";

        var results = new List<Finding>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            results.Add(Map(reader));
        }

        return results;
    }

    public async Task<int> CountAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        return await CountAsync(connection, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<int> CountAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM findings;";
        var scalar = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        return Convert.ToInt32(scalar);
    }

    private static Finding Map(SqliteDataReader reader)
    {
        var properties = JsonSerializer.Deserialize<Dictionary<string, string>>(reader.GetString(8), JsonOptions)
            ?? new Dictionary<string, string>();
        var tags = JsonSerializer.Deserialize<List<string>>(reader.GetString(9), JsonOptions)
            ?? new List<string>();

        return new Finding
        {
            Id = reader.GetString(0),
            Title = reader.GetString(1),
            Domain = Enum.TryParse<AssetDomain>(reader.GetString(2), out var domain) ? domain : AssetDomain.Unknown,
            Severity = (Severity)reader.GetInt32(3),
            Confidence = (Confidence)reader.GetInt32(4),
            Source = reader.GetString(5),
            Principal = reader.IsDBNull(6) ? null : reader.GetString(6),
            Technique = reader.IsDBNull(7) ? null : reader.GetString(7),
            Properties = properties,
            Tags = tags,
            Evidence = reader.IsDBNull(10) ? null : reader.GetString(10),
            DiscoveredAt = DateTimeOffset.Parse(reader.GetString(11)),
        };
    }

    private async Task<SqliteConnection> OpenAsync(CancellationToken cancellationToken)
    {
        var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        return connection;
    }
}
