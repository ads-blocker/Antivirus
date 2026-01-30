using System;
using System.Management;
using System.Threading;

namespace Edr
{
    public sealed class JobCOMMonitoring : IEdrJob
    {
        public string Name { get { return "COMMonitoring"; } }
        public int IntervalSeconds { get { return 120; } }

        public void Run(CancellationToken ct)
        {
            try
            {
                using (var s = new ManagementObjectSearcher("SELECT Caption,Status FROM Win32_COMApplication"))
                using (var r = s.Get())
                {
                    int n = 0;
                    foreach (ManagementBaseObject o in r) { if (ct.IsCancellationRequested) break; n++; }
                    EdrLog.Write(Name, "COM applications enumerated: " + n, "INFO", "com_monitoring.log");
                }
            }
            catch (Exception ex) { EdrLog.Write(Name, "Error: " + ex.Message, "ERROR", "com_monitoring.log"); }
        }
    }
}
