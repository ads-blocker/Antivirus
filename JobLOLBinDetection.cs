using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Threading;

namespace Edr
{
    public sealed class JobLOLBinDetection : IEdrJob
    {
        public string Name { get { return "LOLBinDetection"; } }
        public int IntervalSeconds { get { return 90; } }

        struct LoLBin { public string Name; public string[] Patterns; public string Severity; public string Description; }

        static LoLBin[] Patterns()
        {
            return new[]
            {
                new LoLBin { Name = "certutil", Patterns = new[] { "-decode", "-urlcache", "-verifyctl", "-encode" }, Severity = "HIGH", Description = "Certutil abuse" },
                new LoLBin { Name = "bitsadmin", Patterns = new[] { "transfer", "addfile", "/download" }, Severity = "HIGH", Description = "BITS abuse" },
                new LoLBin { Name = "mshta", Patterns = new[] { "http://", "https://", "javascript:", "vbscript:" }, Severity = "CRITICAL", Description = "MSHTA remote code execution" },
                new LoLBin { Name = "regsvr32", Patterns = new[] { "scrobj.dll", "/s", "/u", "http://", "https://" }, Severity = "HIGH", Description = "Regsvr32 squiblydoo" },
                new LoLBin { Name = "rundll32", Patterns = new[] { "javascript:", "http://", "https://", "shell32.dll,Control_RunDLL" }, Severity = "MEDIUM", Description = "Rundll32 proxy execution" },
                new LoLBin { Name = "wmic", Patterns = new[] { "process call create", "/node:", "format:\"http", "xsl:http" }, Severity = "HIGH", Description = "WMIC remote/XSL abuse" },
                new LoLBin { Name = "powershell", Patterns = new[] { "-enc ", "-encodedcommand", "downloadstring", "iex ", "invoke-expression", "-nop", "-w hidden", "bypass" }, Severity = "HIGH", Description = "PowerShell obfuscation" },
                new LoLBin { Name = "sc", Patterns = new[] { "create", "config", "binpath=" }, Severity = "MEDIUM", Description = "Service manipulation" },
                new LoLBin { Name = "msiexec", Patterns = new[] { "/quiet", "/q", "http://", "https://" }, Severity = "MEDIUM", Description = "Silent MSI from remote" }
            };
        }

        public void Run(CancellationToken ct)
        {
            int self = EdrProcess.CurrentPid;
            var procs = EdrProcess.GetProcesses(ct);
            foreach (var p in procs)
            {
                if (ct.IsCancellationRequested) break;
                if (p.ProcessId == self) continue;
                string cmd = p.CommandLine ?? "";
                if (cmd.Length == 0) continue;
                string pname = (p.Name ?? "").Replace(".exe", "").Replace(".EXE", "");

                foreach (var lb in Patterns())
                {
                    if (pname.IndexOf(lb.Name, StringComparison.OrdinalIgnoreCase) < 0) continue;
                    var matched = new List<string>();
                    foreach (string pat in lb.Patterns)
                    {
                        if (cmd.IndexOf(pat, StringComparison.OrdinalIgnoreCase) >= 0)
                            matched.Add(pat);
                    }
                    if (matched.Count == 0) continue;

                    EdrLog.Write(Name, "LOLBin [" + lb.Severity + "] Process: " + p.Name + " (PID: " + p.ProcessId + ") | " + lb.Description + " | Patterns: " + string.Join(", ", matched) + " | " + cmd, "THREAT", "behavior_detections.log");
                    EdrState.ThreatCount++;
                    var level = lb.Severity == "CRITICAL" ? ThreatLevel.Critical : lb.Severity == "HIGH" ? ThreatLevel.High : ThreatLevel.Medium;
                    EdrGlobalRules.RespondToBehavioralThreat(p.ProcessId, p.Name, p.ExecutablePath, level);
                    break;
                }
            }
        }
    }
}
