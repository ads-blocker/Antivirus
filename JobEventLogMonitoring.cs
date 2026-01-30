using System;
using System.Diagnostics;
using System.Threading;

namespace Edr
{
    public sealed class JobEventLogMonitoring : IEdrJob
    {
        public string Name { get { return "EventLogMonitoring"; } }
        public int IntervalSeconds { get { return 60; } }

        public void Run(CancellationToken ct)
        {
            try
            {
                using (var log = new EventLog("Application"))
                {
                    log.MachineName = ".";
                    int n = log.Entries.Count;
                    if (n > 0)
                    {
                        var e = log.Entries[log.Entries.Count - 1];
                        EdrLog.Write(Name, "Last Application event: " + e.TimeGenerated + " | " + e.Source + " | " + e.InstanceId, "INFO", "eventlog_monitoring.log");
                    }
                }
            }
            catch (Exception ex) { EdrLog.Write(Name, "Error: " + ex.Message, "ERROR", "eventlog_monitoring.log"); }
        }
    }
}
