using System;
using System.Collections.Generic;
using System.Threading;

namespace Edr
{
    public sealed class JobProcessHollowingDetection : IEdrJob
    {
        public string Name { get { return "ProcessHollowingDetection"; } }
        public int IntervalSeconds { get { return 30; } }

        static readonly HashSet<string> SuspiciousParents = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "explorer.exe", "winlogon.exe", "services.exe" };
        static readonly HashSet<string> SuspiciousChildren = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "notepad.exe", "calc.exe", "cmd.exe", "powershell.exe", "wmic.exe", "rundll32.exe" };

        public void Run(CancellationToken ct)
        {
            int self = EdrProcess.CurrentPid;
            var procs = EdrProcess.GetProcesses(ct);

            foreach (var p in procs)
            {
                if (ct.IsCancellationRequested) break;
                if (p.ProcessId == self) continue;

                string path = p.ExecutablePath ?? "";
                if (path.Length == 0) continue;

                var parent = EdrProcess.GetParent(p, procs);
                if (parent != null && SuspiciousParents.Contains(parent.Name ?? "") && SuspiciousChildren.Contains(p.Name ?? ""))
                {
                    EdrLog.Write(Name, "PROCESS HOLLOWING: Suspicious parent-child | " + p.Name + " (PID: " + p.ProcessId + ") | Parent: " + parent.Name, "THREAT", "process_hollowing_detections.log");
                    EdrState.ThreatCount++;
                    EdrGlobalRules.KillIfAllowed(p.ProcessId, p.Name, p.ExecutablePath, ct);
                }
            }
        }
    }
}
