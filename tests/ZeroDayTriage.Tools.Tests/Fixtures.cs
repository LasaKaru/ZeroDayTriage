namespace ZeroDayTriage.Tools.Tests;

/// <summary>Realistic, trimmed tool-output fixtures used across normalizer tests.</summary>
internal static class Fixtures
{
    public const string BloodHoundUsers =
        """
        {
          "meta": { "type": "users", "count": 2, "version": 5 },
          "data": [
            {
              "ObjectIdentifier": "S-1-5-21-111-222-333-1104",
              "Properties": {
                "name": "SVC_SQL@EVILCORP.LOCAL",
                "samaccountname": "SVC_SQL",
                "enabled": true,
                "hasspn": true,
                "serviceprincipalnames": ["MSSQLSvc/db01.evilcorp.local:1433"],
                "dontreqpreauth": false,
                "unconstraineddelegation": false
              },
              "Aces": [
                { "PrincipalSID": "S-1-5-21-111-222-333-1104", "PrincipalName": "SVC_SQL", "RightName": "GenericWrite" }
              ]
            },
            {
              "ObjectIdentifier": "S-1-5-21-111-222-333-1105",
              "Properties": {
                "name": "AUDIT_SVC@EVILCORP.LOCAL",
                "samaccountname": "AUDIT_SVC",
                "enabled": true,
                "hasspn": false,
                "dontreqpreauth": true,
                "unconstraineddelegation": false
              },
              "Aces": []
            }
          ]
        }
        """;

    public const string BloodHoundComputers =
        """
        {
          "meta": { "type": "computers", "count": 1 },
          "data": [
            {
              "Properties": {
                "name": "WEB01.EVILCORP.LOCAL",
                "samaccountname": "WEB01$",
                "enabled": true,
                "unconstraineddelegation": true
              },
              "Aces": [
                { "PrincipalSID": "S-1-5-21-111-222-333-512", "RightName": "GetChangesAll" }
              ]
            }
          ]
        }
        """;

    public const string NetExec =
        """
        SMB         10.10.0.5    445    DC01    [*] Windows Server 2022 (signing:False) (SMBv1:False)
        SMB         10.10.0.5    445    DC01    [+] evilcorp.local\svc_sql:Summer2024!
        SMB         10.10.0.7    445    FS01    [+] evilcorp.local\backupadmin:aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99 (Pwn3d!)
        SMB         10.10.0.9    445    WS09    [-] evilcorp.local\jdoe:WrongPassword STATUS_LOGON_FAILURE
        """;

    public const string Certipy =
        """
        {
          "Certificate Authorities": {},
          "Certificate Templates": {
            "0": {
              "Template Name": "BankUserAuth",
              "Enabled": true,
              "[!] Vulnerabilities": {
                "ESC1": "Enrollee supplies subject and client authentication is enabled."
              }
            },
            "1": {
              "Template Name": "WebServer",
              "Enabled": true
            }
          }
        }
        """;

    public const string Slither =
        """
        {
          "success": true,
          "results": {
            "detectors": [
              {
                "check": "reentrancy-eth",
                "impact": "High",
                "confidence": "Medium",
                "description": "Reentrancy in VaultBank.withdraw()",
                "elements": [ { "type": "function", "name": "VaultBank.withdraw()" } ]
              },
              {
                "check": "naming-convention",
                "impact": "Informational",
                "confidence": "High",
                "description": "cosmetic",
                "elements": []
              }
            ]
          }
        }
        """;
}
