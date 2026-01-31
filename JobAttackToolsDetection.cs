using System;
using System.Collections.Generic;
using System.Threading;

namespace Edr
{
    public sealed class JobAttackToolsDetection : IEdrJob
    {
        public string Name { get { return "AttackToolsDetection"; } }
        public int IntervalSeconds { get { return 90; } }

        static readonly string[] Tools = new[] { "mimikatz", "pwdump", "procdump", "wce", "gsecdump", "cain", "john", "hashcat", "hydra", "medusa", "nmap", "metasploit", "armitage" };

        public void Run(CancellationToken ct)
        {
            int self = EdrProcess.CurrentPid;
            var procs = EdrProcess.GetProcesses(ct);
            foreach (var p in procs)
            {
                if (ct.IsCancellationRequested) break;
                if (p.ProcessId == self) continue;
                string n = (p.Name ?? "").ToLowerInvariant();
                string c = (p.CommandLine ?? "").ToLowerInvariant();
                foreach (string t in Tools)
                {
                    if (n.IndexOf(t, StringComparison.OrdinalIgnoreCase) >= 0 || c.IndexOf(t, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        EdrLog.Write(Name, "Attack tool: " + t + " | " + p.Name + " (PID: " + p.ProcessId + ")", "THREAT", "attack_tools_detection.log");
                        EdrState.ThreatCount++;
                        EdrGlobalRules.KillIfAllowed(p.ProcessId, p.Name, p.ExecutablePath, ct);
                        break;
                    }
                }
            }
        }
    }
}
