using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Threading;

namespace Edr
{
    public sealed class JobAMSIBypassDetection : IEdrJob
    {
        public string Name { get { return "AMSIBypassDetection"; } }
        public int IntervalSeconds { get { return 15; } }

        static readonly string[] BypassPatterns = new[]
        {
            "AmsiUtils", "AmsiScanBuffer", "amsiInitFailed", "Bypass", "amsi.dll",
            "amsiutils", "PatchAmsi", "DisableAmsi", "Remove-Amsi", "Invoke-AmsiBypass",
            "AMSI.*bypass", "bypass.*AMSI", "-nop.*-w.*hidden.*-enc", "amsi.*off", "amsi.*disable",
            "Set-Amsi", "Override.*AMSI", "System.Management.Automation.AmsiUtils"
        };

        public void Run(CancellationToken ct)
        {
            int self = EdrProcess.CurrentPid;
            var procs = EdrProcess.GetProcesses(ct);
            foreach (var p in procs)
            {
                if (ct.IsCancellationRequested) break;
                if (p.ProcessId == self) continue;
                string name = (p.Name ?? "").ToLowerInvariant();
                if (name.IndexOf("powershell") < 0 && name.IndexOf("pwsh") < 0 && name.IndexOf("wscript") < 0 && name.IndexOf("cscript") < 0) continue;
                string cmd = p.CommandLine ?? "";
                if (cmd.Length == 0) continue;

                foreach (string pat in BypassPatterns)
                {
                    if (cmd.IndexOf(pat, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        EdrLog.Write(Name, "AMSI BYPASS: " + p.Name + " (PID: " + p.ProcessId + ") - " + pat, "THREAT", "amsi_bypass_detections.log");
                        EdrState.ThreatCount++;
                        EdrGlobalRules.KillIfAllowed(p.ProcessId, p.Name, p.ExecutablePath, ct);
                        break;
                    }
                }

                if (cmd.IndexOf("-enc", StringComparison.OrdinalIgnoreCase) >= 0 && cmd.IndexOf("-encodedcommand", StringComparison.OrdinalIgnoreCase) >= 0 && cmd.Length > 500)
                {
                    EdrLog.Write(Name, "AMSI BYPASS (obfuscated): " + p.Name + " (PID: " + p.ProcessId + ") long encoded command", "THREAT", "amsi_bypass_detections.log");
                    EdrState.ThreatCount++;
                    EdrGlobalRules.KillIfAllowed(p.ProcessId, p.Name, p.ExecutablePath, ct);
                }
            }

            if (EdrRegistry.IsAmsiDisabled())
            {
                EdrLog.Write(Name, "AMSI BYPASS: Registry tampering HKLM\\SOFTWARE\\Microsoft\\AMSI DisableAMSI", "THREAT", "amsi_bypass_detections.log");
                EdrState.ThreatCount++;
            }
        }
    }
}
