using System;
using System.IO;
using System.Threading;

namespace Edr
{
    public sealed class JobHoneypotMonitoring : IEdrJob
    {
        public string Name { get { return "HoneypotMonitoring"; } }
        public int IntervalSeconds { get { return 90; } }

        public void Run(CancellationToken ct)
        {
            string path = Path.Combine(EdrConfig.InstallPath, "Data", "honeypot");
            try
            {
                if (!Directory.Exists(path)) return;
                int n = 0;
                foreach (string f in Directory.GetFiles(path)) { if (ct.IsCancellationRequested) break; n++; }
                if (n > 0) EdrLog.Write(Name, "Honeypot files: " + n, "INFO", "honeypot.log");
            }
            catch (Exception ex) { EdrLog.Write(Name, "Error: " + ex.Message, "ERROR", "honeypot.log"); }
        }
    }
}
