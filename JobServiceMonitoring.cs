using System;
using System.Management;
using System.Threading;

namespace Edr
{
    public sealed class JobServiceMonitoring : IEdrJob
    {
        public string Name { get { return "ServiceMonitoring"; } }
        public int IntervalSeconds { get { return 60; } }

        public void Run(CancellationToken ct)
        {
            try
            {
                using (var s = new ManagementObjectSearcher("SELECT Name,State,PathName FROM Win32_Service WHERE State = 'Running'"))
                using (var r = s.Get())
                {
                    int n = 0;
                    foreach (ManagementBaseObject o in r) { if (ct.IsCancellationRequested) break; n++; }
                    EdrLog.Write(Name, "Running services: " + n, "INFO", "service_monitoring.log");
                }
            }
            catch (Exception ex) { EdrLog.Write(Name, "Error: " + ex.Message, "ERROR", "service_monitoring.log"); }
        }
    }
}
