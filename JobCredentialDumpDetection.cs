using System;
using System.Collections.Generic;
using System.Threading;

namespace Edr
{
    public sealed class JobCredentialDumpDetection : IEdrJob
    {
        public string Name { get { return "CredentialDumpDetection"; } }
        public int IntervalSeconds { get { return 15; } }

        static readonly string[] CredentialTools = new[] { "mimikatz", "sekurlsa", "pwdump", "gsecdump", "wce", "procdump", "dumpert", "nanodump", "lsassy", "lsadump", "cachedump" };

        public void Run(CancellationToken ct)
        {
            int self = EdrProcess.CurrentPid;
            var procs = EdrProcess.GetProcesses(ct);

            foreach (var p in procs)
            {
                if (ct.IsCancellationRequested) break;
                if (p.ProcessId == self) continue;

                string cmd = (p.CommandLine ?? "").ToLowerInvariant();
                string pname = (p.Name ?? "").ToLowerInvariant();

                if (cmd.IndexOf("lsass", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    EdrLog.Write(Name, "LSASS access - " + p.Name + " (PID: " + p.ProcessId + ") | " + p.CommandLine, "THREAT", "credential_dumping_detections.log");
                    EdrState.ThreatCount++;
                    EdrGlobalRules.KillIfAllowed(p.ProcessId, p.Name, p.ExecutablePath, ct);
                    continue;
                }

                if (cmd.IndexOf("reg", StringComparison.OrdinalIgnoreCase) >= 0 && (cmd.IndexOf("save", StringComparison.OrdinalIgnoreCase) >= 0 || cmd.IndexOf("export", StringComparison.OrdinalIgnoreCase) >= 0) &&
                    (cmd.IndexOf("sam", StringComparison.OrdinalIgnoreCase) >= 0 || cmd.IndexOf("security", StringComparison.OrdinalIgnoreCase) >= 0 || cmd.IndexOf("system", StringComparison.OrdinalIgnoreCase) >= 0))
                {
                    EdrLog.Write(Name, "Registry credential hive access - " + p.Name + " (PID: " + p.ProcessId + ") | " + p.CommandLine, "THREAT", "credential_dumping_detections.log");
                    EdrState.ThreatCount++;
                    EdrGlobalRules.KillIfAllowed(p.ProcessId, p.Name, p.ExecutablePath, ct);
                    continue;
                }

                if (cmd.IndexOf("minidump", StringComparison.OrdinalIgnoreCase) >= 0 || cmd.IndexOf("createdump", StringComparison.OrdinalIgnoreCase) >= 0 || cmd.IndexOf(".dmp", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    EdrLog.Write(Name, "Memory dump creation - " + p.Name + " (PID: " + p.ProcessId + ") | " + p.CommandLine, "WARNING", "credential_dumping_detections.log");
                    continue;
                }

                foreach (string tool in CredentialTools)
                {
                    if (pname.IndexOf(tool, StringComparison.OrdinalIgnoreCase) >= 0 || cmd.IndexOf(tool, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        EdrLog.Write(Name, "Credential dumping tool - " + tool + " | " + p.Name + " (PID: " + p.ProcessId + ") | " + p.CommandLine, "THREAT", "credential_dumping_detections.log");
                        EdrState.ThreatCount++;
                        EdrGlobalRules.KillIfAllowed(p.ProcessId, p.Name, p.ExecutablePath, ct);
                        break;
                    }
                }
            }
        }
    }
}
