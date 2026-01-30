using System;
using System.Collections.Generic;
using System.Threading;

namespace Edr
{
    public sealed class JobCodeInjectionDetection : IEdrJob
    {
        public string Name { get { return "CodeInjectionDetection"; } }
        public int IntervalSeconds { get { return 30; } }

        static readonly string[] Patterns = new[] { "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC" };

        public void Run(CancellationToken ct)
        {
            int self = EdrProcess.CurrentPid;
            var procs = EdrProcess.GetProcesses(ct);
            foreach (var p in procs)
            {
                if (ct.IsCancellationRequested) break;
                if (p.ProcessId == self) continue;
                string c = p.CommandLine ?? "";
                foreach (string pat in Patterns)
                {
                    if (c.IndexOf(pat, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        EdrLog.Write(Name, "CODE INJECTION: " + pat + " | " + p.Name + " (PID: " + p.ProcessId + ")", "THREAT", "code_injection_detections.log");
                        EdrState.ThreatCount++;
                        EdrGlobalRules.KillIfAllowed(p.ProcessId, p.Name, p.ExecutablePath, ct);
                        break;
                    }
                }
            }
        }
    }
}
