using System;
using System.Management;
using System.Threading;

namespace Edr
{
    public sealed class JobWebcamGuardian : IEdrJob
    {
        public string Name { get { return "WebcamGuardian"; } }
        public int IntervalSeconds { get { return 60; } }

        public void Run(CancellationToken ct)
        {
            try
            {
                using (var s = new ManagementObjectSearcher("SELECT Name,Status FROM Win32_PnPEntity WHERE Name LIKE '%camera%' OR Name LIKE '%webcam%' OR Name LIKE '%video%'"))
                using (var r = s.Get())
                {
                    int n = 0;
                    foreach (ManagementBaseObject o in r) { if (ct.IsCancellationRequested) break; n++; }
                    if (n > 0) EdrLog.Write(Name, "Video/camera devices: " + n, "INFO", "webcam_guardian.log");
                }
            }
            catch (Exception ex) { EdrLog.Write(Name, "Error: " + ex.Message, "ERROR", "webcam_guardian.log"); }
        }
    }
}
