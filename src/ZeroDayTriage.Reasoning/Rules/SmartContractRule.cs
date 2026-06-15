using ZeroDayTriage.Core.Abstractions;
using ZeroDayTriage.Core.Model;

namespace ZeroDayTriage.Reasoning.Rules;

/// <summary>
/// Promotes high-impact Solidity static-analysis findings (reentrancy, arbitrary-send,
/// suicidal, unprotected upgrades) into exploitation paths for the blockchain battleground.
/// </summary>
public sealed class SmartContractRule : IAttackPathRule
{
    private static readonly HashSet<string> HighValueChecks = new(StringComparer.OrdinalIgnoreCase)
    {
        "reentrancy-eth", "reentrancy-no-eth", "arbitrary-send-eth", "arbitrary-send",
        "suicidal", "unprotected-upgrade", "controlled-delegatecall", "tx-origin",
    };

    public string Id => "CHAIN-SOLIDITY";

    public string Description => "High-impact Solidity defect -> on-chain exploitation path.";

    public AssetDomain Domain => AssetDomain.SmartContract;

    public IEnumerable<AttackPath> Evaluate(FindingCorpus findings)
    {
        foreach (var f in findings.InDomain(AssetDomain.SmartContract))
        {
            var check = f.Property("check") ?? string.Empty;
            if (f.Severity < Severity.High && !HighValueChecks.Contains(check))
            {
                continue;
            }

            yield return new AttackPath
            {
                Name = $"Exploit {check} in {f.Principal ?? "contract"}",
                Objective = "Drain / hijack smart contract",
                Domain = AssetDomain.SmartContract,
                Impact = f.Severity,
                Confidence = f.Confidence,
                Rationale =
                    $"Slither flagged {check} ({f.Property("impact")}) in {f.Principal ?? "the contract"} -> " +
                    "craft a PoC transaction to exploit it.",
                Steps = new[]
                {
                    new AttackStep
                    {
                        Action = $"Confirm and weaponize {check} with a Foundry test against a fork.",
                        Tooling = "forge test --match-test testExploit -vvvv  # PoC against mainnet/testnet fork",
                        Phase = KillChainPhase.Exploit,
                        EvidenceFindingIds = new[] { f.Id },
                    },
                },
            };
        }
    }
}
