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
        lock (_lock)
        {
            foreach (IEdrJob j in _jobs)
            {
                int interval = Math.Max(1, j.IntervalSeconds) * 1000;
                var t = new Timer(_ => RunJob(j), null, 0, interval);
                _timers[j] = t;
            }
            count = _jobs.Count;
        }
        EdrLog.Write("JobRunner", "Started " + count + " jobs.");
    }

    public void Stop()
    {
        if (_cts != null)
        {
            _cts.Cancel();
            lock (_lock)
            {
                foreach (Timer t in _timers.Values)
                {
                    if (t != null) t.Dispose();
                }
                _timers.Clear();
            }
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
