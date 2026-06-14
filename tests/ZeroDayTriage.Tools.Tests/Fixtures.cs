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

    public const string SuricataEve =
        """
        {"timestamp":"2026-06-14T10:00:01Z","event_type":"alert","src_ip":"10.20.1.44","dest_ip":"185.99.4.10","alert":{"signature":"ET MALWARE SocGholish Fake Browser Update","category":"A Network Trojan was detected","severity":1}}
        {"timestamp":"2026-06-14T10:05:11Z","event_type":"alert","src_ip":"10.20.1.44","dest_ip":"185.99.4.10","alert":{"signature":"ET MALWARE Cobalt Strike Beacon Observed","category":"Malware","severity":1}}
        {"timestamp":"2026-06-14T11:30:00Z","event_type":"alert","src_ip":"10.20.5.9","dest_ip":"185.99.4.10","alert":{"signature":"ET POLICY Large Outbound Data Exfiltration","category":"Policy","severity":2}}
        {"timestamp":"2026-06-14T11:31:00Z","event_type":"flow","src_ip":"10.20.5.9","dest_ip":"8.8.8.8"}
        """;

    public const string RitaBeacons =
        """
        {
          "beacons": [
            { "source": "10.20.1.44", "destination": "185.99.4.10", "score": 0.97, "connections": 1440 },
            { "source": "10.20.2.7", "destination": "9.9.9.9", "score": 0.42, "connections": 18 }
          ]
        }
        """;

    public const string MalwareConfig =
        """
        {
          "family": "Dridex",
          "sample_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "c2": ["185.99.4.10:443", "91.213.50.12:8443"],
          "keys": { "rc4": "8f3ab2c1d4e5f60718293a4b5c6d7e8f", "botnet_id": "22201" },
          "capabilities": ["inject into process", "encrypt C2 using RC4", "steal banking credentials"],
          "iocs": { "mutex": "Global\\\\A1B2C3", "registry": "HKCU\\\\Software\\\\Dridex" }
        }
        """;

    public const string RansomwareConfig =
        """
        {
          "family": "EvilLocker",
          "sample_sha256": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
          "c2": ["10.66.6.6:1337"],
          "keys": { "rsa_pub": "MFwwDQYJ..." },
          "capabilities": ["encrypt files", "delete shadow copies"]
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
