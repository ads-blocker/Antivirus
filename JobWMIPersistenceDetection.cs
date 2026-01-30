using System.Threading;

namespace Edr
{
    public sealed class JobWMIPersistenceDetection : IEdrJob
    {
        public string Name { get { return "WMIPersistenceDetection"; } }
        public int IntervalSeconds { get { return 120; } }

        public void Run(CancellationToken ct)
        {
            foreach (var f in EdrWmi.GetEventFilters())
            {
                if (ct.IsCancellationRequested) break;
                EdrLog.Write(Name, "WMI Event filter: " + f.Name + " | Query: " + (f.Query ?? ""), "INFO", "wmi_persistence.log");
            }
            foreach (var c in EdrWmi.GetCommandLineConsumers())
            {
                if (ct.IsCancellationRequested) break;
                EdrLog.Write(Name, "WMI Command consumer: " + c.Name + " | Command: " + (c.CommandLineTemplate ?? ""), "INFO", "wmi_persistence.log");
            }
        }
    }
}
