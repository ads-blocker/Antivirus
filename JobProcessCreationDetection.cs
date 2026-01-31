using System;
using System.Threading;

namespace Edr
{
    public sealed class JobProcessCreationDetection : IEdrJob
    {
        public string Name { get { return "ProcessCreationDetection"; } }
        public int IntervalSeconds { get { return 120; } }
        static int _tickCount;

        public void Run(CancellationToken ct)
        {
            var procs = EdrProcess.GetProcesses(ct);
            if (++_tickCount % 5 == 0)
                EdrLog.Write(Name, "Process count: " + (procs != null ? procs.Count : 0), "INFO", "process_creation_detections.log");
        }
    }
}
