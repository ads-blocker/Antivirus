using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;

namespace Edr
{
    public sealed class JobAdvancedThreatDetection : IEdrJob
    {
        public string Name { get { return "AdvancedThreatDetection"; } }
        public int IntervalSeconds { get { return 90; } }

        static readonly string[] Paths = new[] { @"C:\Windows\Temp", @"C:\Windows\System32\Tasks" };
        static readonly string[] Ext = new[] { ".exe", ".dll", ".ps1", ".vbs" };

        public void Run(CancellationToken ct)
        {
            foreach (string basePath in Paths)
            {
                if (ct.IsCancellationRequested) break;
                if (!Directory.Exists(basePath)) continue;
                try
                {
                    foreach (string e in Ext)
                    {
                        foreach (string f in Directory.GetFiles(basePath, "*" + e, SearchOption.TopDirectoryOnly))
                        {
                            if (ct.IsCancellationRequested) break;
                            double ent = EdrFile.MeasureEntropy(f);
                            if (ent <= 7.5) continue;
                            if (EdrGlobalRules.QuarantineIfAllowed(f, "AdvancedThreat", ct))
                            {
                                EdrLog.Write(Name, "High-entropy file (CleanGuard): " + f + " | Entropy: " + Math.Round(ent, 2), "THREAT", "advanced_threat_detection.log");
                                EdrState.ThreatCount++;
                            }
                        }
                    }
                }
                catch (Exception ex) { EdrLog.Write(Name, "Error: " + ex.Message, "ERROR", "advanced_threat_detection.log"); }
            }
        }
    }
}
