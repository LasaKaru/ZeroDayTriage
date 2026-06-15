using ZeroDayTriage.Core.Model;

namespace ZeroDayTriage.Core.Abstractions;

/// <summary>
/// Persistence boundary for findings. The default implementation is SQLite-backed, but
/// the engine and CLI depend only on this interface.
/// </summary>
public interface IFindingStore
{
    Task InitializeAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Upserts findings by <see cref="Finding.Id"/>. Returns the number of rows that were
    /// newly inserted (duplicates are ignored, not double-counted).
    /// </summary>
    Task<int> UpsertAsync(IEnumerable<Finding> findings, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<Finding>> GetAllAsync(CancellationToken cancellationToken = default);

    Task<int> CountAsync(CancellationToken cancellationToken = default);
}
