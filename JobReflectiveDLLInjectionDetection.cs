using System;
using System.Collections.Generic;
using System.Threading;

namespace Edr
{
    public sealed class JobReflectiveDLLInjectionDetection : IEdrJob
    {
        public string Name { get { return "ReflectiveDLLInjectionDetection"; } }
        public int IntervalSeconds { get { return 90; } }

        static readonly string[] Patterns = new[] { "ReflectiveLoader", "LoadLibraryR", "LdrLoadDll", "NtMapViewOfSection", "VirtualAllocEx", "WriteProcessMemory" };

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
                        EdrLog.Write(Name, "Reflective DLL: " + pat + " | " + p.Name + " (PID: " + p.ProcessId + ")", "THREAT", "reflective_dll_detections.log");
                        EdrState.ThreatCount++;
                        EdrGlobalRules.KillIfAllowed(p.ProcessId, p.Name, p.ExecutablePath, ct);
                        break;
                    }
                }
            }
        }
    }
}
