using System;
using System.Management;
using System.Threading;

namespace Edr
{
    public sealed class JobMobileDeviceMonitoring : IEdrJob
    {
        public string Name { get { return "MobileDeviceMonitoring"; } }
        public int IntervalSeconds { get { return 90; } }

        public void Run(CancellationToken ct)
        {
            try
            {
                using (var s = new ManagementObjectSearcher("SELECT Caption,DeviceID FROM Win32_PnPEntity WHERE Caption LIKE '%portable%' OR Caption LIKE '%USB%' OR Caption LIKE '%MTP%'"))
                using (var r = s.Get())
                {
                    int n = 0;
                    foreach (ManagementBaseObject o in r) { if (ct.IsCancellationRequested) break; n++; }
                    if (n > 0) EdrLog.Write(Name, "Portable/MTP devices: " + n, "INFO", "mobile_device_monitoring.log");
                }
            }
            catch (Exception ex) { EdrLog.Write(Name, "Error: " + ex.Message, "ERROR", "mobile_device_monitoring.log"); }
        }
    }
}
