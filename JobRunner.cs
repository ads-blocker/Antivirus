using System;
using System.Collections.Generic;
using System.Threading;

namespace Edr
{
    public sealed class JobRunner
    {
    readonly object _lock = new object();
    readonly List<IEdrJob> _jobs = new List<IEdrJob>();
    readonly Dictionary<IEdrJob, Timer> _timers = new Dictionary<IEdrJob, Timer>();
    CancellationTokenSource _cts;

    public void Register(IEdrJob job)
    {
        if (job == null) return;
        lock (_lock) { _jobs.Add(job); }
    }

    public void Start()
    {
        Stop();
        _cts = new CancellationTokenSource();
        int count;
        int index = 0;
        lock (_lock)
        {
            foreach (IEdrJob j in _jobs)
            {
                int interval = Math.Max(1, j.IntervalSeconds) * 1000;
                int staggerMs = Math.Min(index * 1500, interval - 1000);
                var t = new Timer(_ => RunJob(j), null, staggerMs, interval);
                _timers[j] = t;
                index++;
            }
            count = _jobs.Count;
        }
        EdrLog.Write("JobRunner", "Started " + count + " jobs (staggered).");
    }

    public void Stop()
    {
        if (_cts != null)
        {
            _cts.Cancel();
            Timer[] toDispose;
            lock (_lock)
            {
                foreach (Timer t in _timers.Values)
                {
                    if (t != null)
                        t.Change(System.Threading.Timeout.Infinite, System.Threading.Timeout.Infinite);
                }
                toDispose = new Timer[_timers.Count];
                _timers.Values.CopyTo(toDispose, 0);
                _timers.Clear();
            }
            System.Threading.ThreadPool.QueueUserWorkItem(_ => { foreach (var t in toDispose) try { if (t != null) t.Dispose(); } catch { } });
            _cts = null;
        }
    }

        void RunJob(IEdrJob job)
        {
            if (_cts == null || _cts.IsCancellationRequested) return;
            try
            {
                job.Run(_cts.Token);
            }
            catch (Exception ex)
            {
                EdrLog.Write(job.Name, "Error: " + ex.Message, "ERROR");
            }
        }
    }
}
