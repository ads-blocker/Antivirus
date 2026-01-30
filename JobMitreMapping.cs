using System;
using System.Collections.Generic;
using System.Threading;

namespace Edr
{
    public sealed class JobMitreMapping : IEdrJob
    {
        public string Name { get { return "MitreMapping"; } }
        public int IntervalSeconds { get { return 120; } }

        static readonly Dictionary<string, string> Map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "LOLBin", "T1218" },
            { "CredentialDump", "T1003" },
            { "AMSIBypass", "T1562.001" },
            { "ProcessHollowing", "T1055.012" },
            { "Keylogger", "T1056.001" },
            { "Ransomware", "T1486" },
            { "CodeInjection", "T1055" },
            { "LateralMovement", "T1021" },
            { "DLLHijacking", "T1574.001" },
            { "TokenManipulation", "T1134" },
            { "RegistryPersistence", "T1547.001" },
            { "ScheduledTask", "T1053.005" },
            { "WMIPersistence", "T1546.003" },
            { "DataExfiltration", "T1041" },
            { "Beacon", "T1071" },
            { "AttackTools", "T1588" }
        };

        public void Run(CancellationToken ct)
        {
            EdrLog.Write(Name, "MITRE mapping tick | ThreatCount: " + EdrState.ThreatCount, "INFO", "mitre_detections.log");
        }

        public static string GetTechnique(string detectionType)
        {
            string t;
            return Map.TryGetValue(detectionType ?? "", out t) ? t : null;
        }
    }
}
