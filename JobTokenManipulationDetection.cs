using System;
using System.Diagnostics;
using System.IO;
using System.Threading;

namespace Edr
{
    public sealed class JobTokenManipulationDetection : IEdrJob
    {
        public string Name { get { return "TokenManipulationDetection"; } }
        public int IntervalSeconds { get { return 60; } }

        public void Run(CancellationToken ct)
        {
            int self = EdrProcess.CurrentPid;
            string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows) ?? "C:\\Windows";

            foreach (var proc in Process.GetProcesses())
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    if (proc.Id == self) { proc.Dispose(); continue; }
                    string path = null;
                    try { path = proc.MainModule != null ? proc.MainModule.FileName : null; } catch { }
                    if (string.IsNullOrEmpty(path)) { proc.Dispose(); continue; }

                    string domain, user;
                    if (!EdrProcess.GetOwner(proc.Id, out domain, out user)) { proc.Dispose(); continue; }
                    if (string.IsNullOrEmpty(domain) || domain.IndexOf("NT AUTHORITY", StringComparison.OrdinalIgnoreCase) < 0) { proc.Dispose(); continue; }
                    if ((path ?? "").StartsWith(win, StringComparison.OrdinalIgnoreCase)) { proc.Dispose(); continue; }

                    EdrLog.Write(Name, "SUSPICIOUS: Non-system binary as SYSTEM | " + proc.ProcessName + " | " + path, "THREAT", "token_manipulation.log");
                    EdrState.ThreatCount++;
                    EdrGlobalRules.KillIfAllowed(proc.Id, proc.ProcessName, path, ct);
                }
                catch { }
                finally { try { proc.Dispose(); } catch { } }
            }
        }
    }
}
