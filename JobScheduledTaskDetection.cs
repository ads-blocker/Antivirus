using System.Threading;

namespace Edr
{
    public sealed class JobScheduledTaskDetection : IEdrJob
    {
        public string Name { get { return "ScheduledTaskDetection"; } }
        public int IntervalSeconds { get { return 120; } }

        public void Run(CancellationToken ct)
        {
            foreach (var t in EdrScheduledTask.QueryTasks())
            {
                if (ct.IsCancellationRequested) break;
                if (!EdrScheduledTask.IsSuspicious(t)) continue;
                EdrLog.Write(Name, "SUSPICIOUS ScheduledTask: " + t.TaskName + " | Action: " + t.Execute + " | User: " + t.RunAsUser, "THREAT", "scheduled_task_detections.log");
                EdrState.ThreatCount++;
            }
        }
    }
}
