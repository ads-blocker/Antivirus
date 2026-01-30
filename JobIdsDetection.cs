using System;
using System.Collections.Generic;
using System.Threading;

namespace Edr
{
    public sealed class JobIdsDetection : IEdrJob
    {
        public string Name { get { return "IdsDetection"; } }
        public int IntervalSeconds { get { return 45; } }

        static readonly string[] IdsSignatures = new[]
        {
            "meterpreter", "reverse_shell", "bind_shell", "exploit/", "payload",
            "cmd.exe /c", "powershell -enc", "rundll32 javascript:", "mshta http",
            "certutil -urlcache", "bitsadmin /transfer", "regsvr32 /s /n /u",
            "Invoke-Mimikatz", "sekurlsa::", " Invoke-WebRequest ", "Net.WebClient"
        };

        public void Run(CancellationToken ct)
        {
            int self = EdrProcess.CurrentPid;
            var procs = EdrProcess.GetProcesses(ct);
            foreach (var p in procs)
            {
                if (ct.IsCancellationRequested) break;
                if (p.ProcessId == self) continue;
                string cmd = (p.CommandLine ?? "").ToLowerInvariant();
                foreach (string sig in IdsSignatures)
                {
                    if (cmd.IndexOf(sig, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        EdrLog.Write(Name, "IDS signature: " + sig + " | " + p.Name + " (PID: " + p.ProcessId + ")", "THREAT", "ids_detections.log");
                        EdrState.ThreatCount++;
                        EdrGlobalRules.KillIfAllowed(p.ProcessId, p.Name, p.ExecutablePath, ct);
                        break;
                    }
                }
            }
        }
    }
}
