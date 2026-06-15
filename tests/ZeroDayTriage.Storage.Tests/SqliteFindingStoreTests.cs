using FluentAssertions;
using ZeroDayTriage.Core.Model;
using ZeroDayTriage.Storage;
using Xunit;

namespace ZeroDayTriage.Storage.Tests;

public sealed class SqliteFindingStoreTests : IAsyncLifetime, IDisposable
{
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"ztriage_{Guid.NewGuid():N}.db");
    private SqliteFindingStore _store = null!;

    public async Task InitializeAsync()
    {
        _store = SqliteFindingStore.ForFile(_dbPath);
        await _store.InitializeAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    private static Finding Sample(
        string title = "Kerberoastable: SVC_SQL",
        Severity severity = Severity.High,
        Confidence confidence = Confidence.Confirmed) => new Finding
        {
            Title = title,
            Source = "sharphound",
            Domain = AssetDomain.ActiveDirectory,
            Principal = "EVILCORP\\SVC_SQL",
            Technique = "T1558.003",
            Severity = severity,
            Confidence = confidence,
            Tags = new[] { "kerberoastable", "ad" },
            Properties = new Dictionary<string, string> { ["spn"] = "MSSQLSvc/db01" },
            Evidence = "hasspn=true",
        }.WithComputedId();

    [Fact]
    public async Task Upsert_then_GetAll_roundtrips_all_fields()
    {
        await _store.UpsertAsync(new[] { Sample() });

        var stored = (await _store.GetAllAsync()).Single();

        stored.Title.Should().Be("Kerberoastable: SVC_SQL");
        stored.Domain.Should().Be(AssetDomain.ActiveDirectory);
        stored.Severity.Should().Be(Severity.High);
        stored.Tags.Should().Contain("kerberoastable");
        stored.Properties["spn"].Should().Be("MSSQLSvc/db01");
        stored.Evidence.Should().Be("hasspn=true");
    }

    [Fact]
    public async Task Upsert_is_idempotent_by_fingerprint()
    {
        var first = await _store.UpsertAsync(new[] { Sample() });
        var second = await _store.UpsertAsync(new[] { Sample() });

        first.Should().Be(1);
        second.Should().Be(0); // duplicate, no new row
        (await _store.CountAsync()).Should().Be(1);
    }

    [Fact]
    public async Task Upsert_escalates_severity_and_confidence_but_never_downgrades()
    {
        await _store.UpsertAsync(new[] { Sample(severity: Severity.Medium, confidence: Confidence.Suspected) });
        await _store.UpsertAsync(new[] { Sample(severity: Severity.Critical, confidence: Confidence.Confirmed) });
        // A later, weaker sighting must not lower the record.
        await _store.UpsertAsync(new[] { Sample(severity: Severity.Low, confidence: Confidence.Suspected) });

        var stored = (await _store.GetAllAsync()).Single();

        stored.Severity.Should().Be(Severity.Critical);
        stored.Confidence.Should().Be(Confidence.Confirmed);
    }

    [Fact]
    public async Task Count_reflects_distinct_findings()
    {
        await _store.UpsertAsync(new[]
        {
            Sample("a"),
            Sample("b"),
            Sample("a"), // duplicate of the first
        });

        (await _store.CountAsync()).Should().Be(2);
    }

    [Fact]
    public async Task GetAll_on_empty_store_returns_empty()
    {
        (await _store.GetAllAsync()).Should().BeEmpty();
    }

    [Fact]
    public async Task Findings_without_id_are_assigned_one_on_upsert()
    {
        var noId = new Finding { Title = "x", Source = "test" };
        noId.Id.Should().BeEmpty();

        await _store.UpsertAsync(new[] { noId });

        (await _store.GetAllAsync()).Single().Id.Should().NotBeEmpty();
    }

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        if (File.Exists(_dbPath))
        {
            File.Delete(_dbPath);
        }
    }
}
