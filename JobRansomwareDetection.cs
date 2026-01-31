using System;
using System.Collections.Generic;
using System.Threading;

namespace Edr
{
    public sealed class JobRansomwareDetection : IEdrJob
    {
        public string Name { get { return "RansomwareDetection"; } }
        public int IntervalSeconds { get { return 90; } }

        static readonly string[] Patterns = new[] { "vssadmin delete shadows", "vssadmin.exe delete", "wbadmin delete catalog", "bcdedit", "shadow copy", "shadowcopy", "cryptolocker", "wannacry", ".encrypted", ".locked", ".crypto" };

        public void Run(CancellationToken ct)
        {
            int self = EdrProcess.CurrentPid;
            var procs = EdrProcess.GetProcesses(ct);
            foreach (var p in procs)
            {
                if (ct.IsCancellationRequested) break;
                if (p.ProcessId == self) continue;
                string cmd = (p.CommandLine ?? "").ToLowerInvariant();
                foreach (string pat in Patterns)
                {
                    if (cmd.IndexOf(pat, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        EdrLog.Write(Name, "RANSOMWARE: " + p.Name + " (PID: " + p.ProcessId + ") | " + pat, "THREAT", "ransomware_detections.log");
                        EdrState.ThreatCount++;
                        EdrGlobalRules.RespondToBehavioralThreat(p.ProcessId, p.Name, p.ExecutablePath, ThreatLevel.Critical);
                        break;
                    }
                }
            }
        }
    }
}
