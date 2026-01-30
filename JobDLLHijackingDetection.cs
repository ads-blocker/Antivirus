using System;
using System.Diagnostics;
using System.Threading;

namespace Edr
{
    public sealed class JobDLLHijackingDetection : IEdrJob
    {
        public string Name { get { return "DLLHijackingDetection"; } }
        public int IntervalSeconds { get { return 90; } }

        public void Run(CancellationToken ct)
        {
            int self = EdrProcess.CurrentPid;
            foreach (var proc in Process.GetProcesses())
            {
                if (ct.IsCancellationRequested) break;
                if (proc.Id == self) { proc.Dispose(); continue; }
                try
                {
                    foreach (ProcessModule m in proc.Modules)
                    {
                        if (ct.IsCancellationRequested) break;
                        string path = m != null ? m.FileName : null;
                        if (string.IsNullOrEmpty(path) || path.IndexOf(".dll", StringComparison.OrdinalIgnoreCase) < 0) continue;
                        if (!EdrFile.IsSuspiciousDllPath(path)) continue;

                        EdrLog.Write(Name, "DLL HIJACKING: Suspicious DLL | " + proc.ProcessName + " (PID: " + proc.Id + ") | " + path, "THREAT", "dll_hijacking_detections.log");
                        EdrState.ThreatCount++;
                        EdrGlobalRules.KillIfAllowed(proc.Id, proc.ProcessName, EdrProcess.GetExecutablePath(proc.Id), ct);
                        break;
                    }
                }
                catch { }
                finally { try { proc.Dispose(); } catch { } }
            }
        }
    }
}
