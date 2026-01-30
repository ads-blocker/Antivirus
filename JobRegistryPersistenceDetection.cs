using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Threading;

namespace Edr
{
    public sealed class JobRegistryPersistenceDetection : IEdrJob
    {
        public string Name { get { return "RegistryPersistenceDetection"; } }
        public int IntervalSeconds { get { return 120; } }

        static readonly Regex[] Suspicious = new[]
        {
            new Regex("powershell.*-enc", RegexOptions.IgnoreCase),
            new Regex("cmd.*/c.*powershell", RegexOptions.IgnoreCase),
            new Regex("https?://", RegexOptions.IgnoreCase),
            new Regex("\\.vbs|\\.js|\\.bat|\\.cmd", RegexOptions.IgnoreCase),
            new Regex("wscript|cscript|mshta", RegexOptions.IgnoreCase),
            new Regex("rundll32.*\\.dll", RegexOptions.IgnoreCase),
            new Regex("regsvr32.*\\.dll", RegexOptions.IgnoreCase)
        };

        public void Run(CancellationToken ct)
        {
            var entries = new List<EdrRegistry.RunEntry>();
            entries.AddRange(EdrRegistry.GetRunEntries(true, true));

            foreach (var e in entries)
            {
                if (ct.IsCancellationRequested) break;
                string v = e.Value ?? "";
                if (v.Length == 0) continue;

                foreach (var r in Suspicious)
                {
                    if (!r.IsMatch(v)) continue;
                    EdrLog.Write(Name, "REGISTRY PERSISTENCE: " + e.KeyName + " | " + e.ValueName + " | " + v, "THREAT", "registry_persistence_detections.log");
                    EdrState.ThreatCount++;
                    break;
                }
            }
        }
    }
}
