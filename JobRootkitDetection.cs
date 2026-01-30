using System;
using System.Management;
using System.Threading;

namespace Edr
{
    public sealed class JobRootkitDetection : IEdrJob
    {
        public string Name { get { return "RootkitDetection"; } }
        public int IntervalSeconds { get { return 180; } }

        public void Run(CancellationToken ct)
        {
            try
            {
                using (var s = new ManagementObjectSearcher("SELECT Name,PathName,State FROM Win32_Service WHERE State = 'Running'"))
                using (var r = s.Get())
                {
                    foreach (ManagementBaseObject o in r)
                    {
                        if (ct.IsCancellationRequested) break;
                        var mo = (ManagementObject)o;
                        string path = mo["PathName"] != null ? mo["PathName"].ToString() : "";
                        if (path.Length == 0) continue;
                        if (path.IndexOf("system32", StringComparison.OrdinalIgnoreCase) >= 0) continue;
                        if (path.IndexOf("windows", StringComparison.OrdinalIgnoreCase) >= 0) continue;
                        EdrLog.Write(Name, "Non-standard running service: " + (mo["Name"] ?? "") + " | " + path, "WARNING", "rootkit_detections.log");
                    }
                }
            }
            catch (Exception ex) { EdrLog.Write(Name, "Error: " + ex.Message, "ERROR", "rootkit_detections.log"); }
        }
    }
}
