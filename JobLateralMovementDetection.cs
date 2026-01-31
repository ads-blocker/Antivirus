using System;
using System.Collections.Generic;
using System.Threading;

namespace Edr
{
    public sealed class JobLateralMovementDetection : IEdrJob
    {
        public string Name { get { return "LateralMovementDetection"; } }
        public int IntervalSeconds { get { return 90; } }

        static readonly string[] Patterns = new[] { "psexec", "wmic /node:", "winrs ", "sc \\\\", "schtasks /s ", "at \\\\", "copy \\\\", "net use" };

        public void Run(CancellationToken ct)
        {
            int self = EdrProcess.CurrentPid;
            var procs = EdrProcess.GetProcesses(ct);
            foreach (var p in procs)
            {
                if (ct.IsCancellationRequested) break;
                if (p.ProcessId == self) continue;
                string c = (p.CommandLine ?? "").ToLowerInvariant();
                foreach (string pat in Patterns)
                {
                    if (c.IndexOf(pat, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        EdrLog.Write(Name, "Lateral movement: " + pat + " | " + p.Name + " (PID: " + p.ProcessId + ")", "THREAT", "lateral_movement.log");
                        EdrState.ThreatCount++;
                        EdrGlobalRules.KillIfAllowed(p.ProcessId, p.Name, p.ExecutablePath, ct);
                        break;
                    }
                }
            }
        }
    }
}
