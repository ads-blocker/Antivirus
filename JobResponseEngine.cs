using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;

namespace Edr
{
    public sealed class JobResponseEngine : IEdrJob
    {
        public string Name { get { return "ResponseEngine"; } }
        public int IntervalSeconds { get { return 180; } }

        static readonly string[] Ext = new[] { ".exe", ".dll", ".sys", ".winmd" };
        const int MaxFilesPerRun = 100;

        public void Run(CancellationToken ct)
        {
            int handled = 0;
            foreach (string basePath in EdrFile.GetSuspiciousScanPaths())
            {
                if (ct.IsCancellationRequested) break;
                if (handled >= MaxFilesPerRun) break;
                if (!Directory.Exists(basePath)) continue;
                try
                {
                    foreach (string e in Ext)
                    {
                        foreach (string f in Directory.GetFiles(basePath, "*" + e, SearchOption.AllDirectories))
                        {
                            if (ct.IsCancellationRequested || handled >= MaxFilesPerRun) break;
                            if (!File.Exists(f)) continue;
                            if (EdrWhitelist.IsWhitelistedPath(f)) continue;
                            if (EdrGlobalRules.QuarantineIfAllowed(f, "ResponseEngine", ct))
                            {
                                EdrLog.Write(Name, "CleanGuard Malicious -> quarantined " + f, "THREAT", "response_engine.log");
                                EdrState.ThreatCount++;
                                handled++;
                            }
                        }
                    }
                }
                catch { }
            }

            if (handled > 0 || EdrState.ThreatCount > 0)
                EdrLog.Write(Name, "Tick | Threats: " + EdrState.ThreatCount + " | Terminated: " + EdrState.ProcessesTerminated + " | Quarantined: " + EdrState.FilesQuarantined + " | Handled: " + handled, "INFO", "response_engine.log");
        }
    }
}
