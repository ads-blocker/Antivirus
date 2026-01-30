using System;
using System.IO;
using System.Threading;

namespace Edr
{
    public sealed class JobQuarantineManagement : IEdrJob
    {
        public string Name { get { return "QuarantineManagement"; } }
        public int IntervalSeconds { get { return 300; } }

        public void Run(CancellationToken ct)
        {
            try
            {
                if (!Directory.Exists(EdrConfig.QuarantinePath)) return;
                int n = 0;
                foreach (string f in Directory.GetFiles(EdrConfig.QuarantinePath)) { if (ct.IsCancellationRequested) break; n++; }
                EdrLog.Write(Name, "Quarantine count: " + n, "INFO", "quarantine_management.log");
            }
            catch (Exception ex) { EdrLog.Write(Name, "Error: " + ex.Message, "ERROR", "quarantine_management.log"); }
        }
    }
}
