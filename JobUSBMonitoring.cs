using System;
using System.Management;
using System.Threading;

namespace Edr
{
    public sealed class JobUSBMonitoring : IEdrJob
    {
        public string Name { get { return "USBMonitoring"; } }
        public int IntervalSeconds { get { return 20; } }

        public void Run(CancellationToken ct)
        {
            try
            {
                using (var s = new ManagementObjectSearcher("SELECT Caption,DeviceID FROM Win32_DiskDrive WHERE InterfaceType = 'USB'"))
                using (var r = s.Get())
                {
                    foreach (ManagementBaseObject o in r)
                    {
                        if (ct.IsCancellationRequested) break;
                        var mo = (ManagementObject)o;
                        EdrLog.Write(Name, "USB drive: " + (mo["Caption"] ?? "") + " | " + (mo["DeviceID"] ?? ""), "INFO", "usb_monitoring.log");
                    }
                }
            }
            catch (Exception ex) { EdrLog.Write(Name, "Error: " + ex.Message, "ERROR", "usb_monitoring.log"); }
        }
    }
}
