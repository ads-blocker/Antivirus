using System;
using System.Threading;

namespace Edr
{
    public sealed class JobProcessCreationDetection : IEdrJob
    {
        public string Name { get { return "ProcessCreationDetection"; } }
        public int IntervalSeconds { get { return 10; } }

        public void Run(CancellationToken ct)
        {
            var procs = EdrProcess.GetProcesses(ct);
            EdrLog.Write(Name, "Process count: " + (procs != null ? procs.Count : 0), "INFO", "process_creation_detections.log");
        }
    }
}
