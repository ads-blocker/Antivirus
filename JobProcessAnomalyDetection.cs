using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Threading;

namespace Edr
{
    public sealed class JobProcessAnomalyDetection : IEdrJob
    {
        public string Name { get { return "ProcessAnomalyDetection"; } }
        public int IntervalSeconds { get { return 15; } }

        static readonly Regex OfficeParent = new Regex("winword|excel|powerpnt|outlook", RegexOptions.IgnoreCase);
        static readonly Regex ScriptChild = new Regex("powershell|cmd|wscript|cscript", RegexOptions.IgnoreCase);
        static readonly Regex HiddenScript = new Regex("-w hidden|-windowstyle hidden|-nop|-enc", RegexOptions.IgnoreCase);
        static readonly Regex UserDir = new Regex(@"Users\\.*\\AppData|Users\\.*\\Downloads|Users\\.*\\Desktop", RegexOptions.IgnoreCase);
        static readonly string[] SystemBinaries = new[] { "svchost.exe", "lsass.exe", "csrss.exe", "smss.exe" };
        static readonly Regex Base64 = new Regex("-enc |-encodedcommand |FromBase64String", RegexOptions.IgnoreCase);
        static readonly Regex EpBypass = new Regex("-exec bypass|-executionpolicy bypass|-ep bypass", RegexOptions.IgnoreCase);
        static readonly Regex DownloadCradle = new Regex("DownloadString|DownloadFile|WebClient|Invoke-WebRequest|wget |curl ", RegexOptions.IgnoreCase);

        public void Run(CancellationToken ct)
        {
            int self = EdrProcess.CurrentPid;
            var procs = EdrProcess.GetProcesses(ct);
            foreach (var proc in procs)
            {
                if (ct.IsCancellationRequested) break;
                if (proc.ProcessId == self) continue;

                int score = 0;
                var anomalies = new List<string>();

                var parent = EdrProcess.GetParent(proc, procs);
                if (parent != null)
                {
                    if (OfficeParent.IsMatch(parent.Name ?? "") && ScriptChild.IsMatch(proc.Name ?? "")) { score += 5; anomalies.Add("OfficeSpawnScript"); }
                    if (string.Equals((parent.Name ?? ""), "explorer.exe", StringComparison.OrdinalIgnoreCase) && HiddenScript.IsMatch(proc.CommandLine ?? "")) { score += 4; anomalies.Add("ExplorerHiddenScript"); }
                    if (string.Equals((parent.Name ?? ""), "svchost.exe", StringComparison.OrdinalIgnoreCase))
                    {
                        string n = (proc.Name ?? "").ToLowerInvariant();
                        if (n.IndexOf("dllhost") < 0 && n.IndexOf("conhost") < 0 && n.IndexOf("rundll32") < 0) { score += 3; anomalies.Add("SvchostUnexpectedChild"); }
                    }
                }

                string path = proc.ExecutablePath ?? "";
                if (path.Length > 0)
                {
                    if (UserDir.IsMatch(path) && (proc.Name ?? "").EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) { score += 2; anomalies.Add("UserDirExecution"); }
                    foreach (string sys in SystemBinaries)
                    {
                        if (!string.Equals(proc.Name, sys, StringComparison.OrdinalIgnoreCase)) continue;
                        if (path.IndexOf("\\Windows\\System32", StringComparison.OrdinalIgnoreCase) < 0) { score += 6; anomalies.Add("SystemBinaryWrongLocation"); }
                        break;
                    }
                }

                string cmd = proc.CommandLine ?? "";
                if (cmd.Length > 0)
                {
                    if (Base64.IsMatch(cmd)) { score += 3; anomalies.Add("Base64Encoding"); }
                    if (EpBypass.IsMatch(cmd)) { score += 2; anomalies.Add("ExecutionPolicyBypass"); }
                    if (DownloadCradle.IsMatch(cmd)) { score += 3; anomalies.Add("DownloadCradle"); }
                }

                if (score >= 6)
                {
                    EdrLog.Write(Name, "CRITICAL process anomaly - " + proc.Name + " (PID: " + proc.ProcessId + ") | Parent: " + (parent != null ? parent.Name : "") + " | Score: " + score + " | " + string.Join(", ", anomalies) + " | " + path + " | " + cmd, "THREAT", "behavior_detections.log");
                    EdrState.ThreatCount++;
                    EdrGlobalRules.KillIfAllowed(proc.ProcessId, proc.Name, proc.ExecutablePath, ct);
                }
                else if (score >= 3)
                {
                    EdrLog.Write(Name, "Process anomaly - " + proc.Name + " (PID: " + proc.ProcessId + ") | Score: " + score + " | " + string.Join(", ", anomalies), "WARNING", "behavior_detections.log");
                }
            }
        }
    }
}
