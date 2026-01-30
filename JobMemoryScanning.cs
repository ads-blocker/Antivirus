using System;
using System.Diagnostics;
using System.Threading;

namespace Edr
{
    public sealed class JobMemoryScanning : IEdrJob
    {
        public string Name { get { return "MemoryScanning"; } }
        public int IntervalSeconds { get { return 90; } }

        public void Run(CancellationToken ct)
        {
            try
            {
                long total = 0;
                foreach (var p in Process.GetProcesses())
                {
                    if (ct.IsCancellationRequested) break;
                    try { total += p.WorkingSet64; } catch { }
                    finally { try { p.Dispose(); } catch { } }
                }
                EdrLog.Write(Name, "Total working set (all processes): " + (total / (1024 * 1024)) + " MB", "INFO", "memory_scanning.log");
            }
            catch (Exception ex) { EdrLog.Write(Name, "Error: " + ex.Message, "ERROR", "memory_scanning.log"); }
        }
    }
}
