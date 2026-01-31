using System;
using System.Collections.Generic;
using System.Threading;

namespace Edr
{
    public sealed class JobFilelessDetection : IEdrJob
    {
        public string Name { get { return "FilelessDetection"; } }
        public int IntervalSeconds { get { return 20; } }

        static readonly string[] FilelessIndicators = new[] { "-enc ", "-encodedcommand", "iex(", "invoke-expression", "frombase64string", "scriptblock", "reflection.assembly" };

        public void Run(CancellationToken ct)
        {
            int self = EdrProcess.CurrentPid;
            var procs = EdrProcess.GetProcesses(ct);
            foreach (var p in procs)
            {
                if (ct.IsCancellationRequested) break;
                if (p.ProcessId == self) continue;
                string n = (p.Name ?? "").ToLowerInvariant();
                if (n.IndexOf("powershell") < 0 && n.IndexOf("pwsh") < 0 && n.IndexOf("wscript") < 0 && n.IndexOf("cscript") < 0) continue;
                string c = (p.CommandLine ?? "").ToLowerInvariant();
                foreach (string pat in FilelessIndicators)
                {
                    if (c.IndexOf(pat, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        EdrLog.Write(Name, "Fileless indicator: " + pat + " | " + p.Name + " (PID: " + p.ProcessId + ")", "THREAT", "fileless_detection.log");
                        EdrState.ThreatCount++;
                        EdrGlobalRules.RespondToBehavioralThreat(p.ProcessId, p.Name, p.ExecutablePath, ThreatLevel.High);
                        break;
                    }
                }
            }
        }
    }
}
