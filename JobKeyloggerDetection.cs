using System;
using System.Collections.Generic;
using System.Threading;

namespace Edr
{
    public sealed class JobKeyloggerDetection : IEdrJob
    {
        public string Name { get { return "KeyloggerDetection"; } }
        public int IntervalSeconds { get { return 45; } }

        static readonly string[] Patterns = new[] { "keylogger", "keylog", "keystroke", "keyboard.*hook", "GetAsyncKeyState", "SetWindowsHookEx", "WH_KEYBOARD" };

        public void Run(CancellationToken ct)
        {
            int self = EdrProcess.CurrentPid;
            var procs = EdrProcess.GetProcesses(ct);
            foreach (var p in procs)
            {
                if (ct.IsCancellationRequested) break;
                if (p.ProcessId == self) continue;
                string cmd = (p.CommandLine ?? "") + " " + (p.Name ?? "");
                foreach (string pat in Patterns)
                {
                    if (cmd.IndexOf(pat, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        EdrLog.Write(Name, "KEYLOGGER: " + p.Name + " (PID: " + p.ProcessId + ") | " + pat, "THREAT", "keylogger_detections.log");
                        EdrState.ThreatCount++;
                        EdrGlobalRules.KillIfAllowed(p.ProcessId, p.Name, p.ExecutablePath, ct);
                        break;
                    }
                }
            }
        }
    }
}
