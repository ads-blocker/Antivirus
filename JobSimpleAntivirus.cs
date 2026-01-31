using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;

namespace Edr
{
    public sealed class JobSimpleAntivirus : IEdrJob
    {
        public string Name { get { return "SimpleAntivirus"; } }
        public int IntervalSeconds { get { return 120; } }

        static readonly string[] Ext = new[] { ".dll", ".winmd" };
        const int MaxUnsignedPerRun = 50;

        public void Run(CancellationToken ct)
        {
            foreach (string path in EdrBrowserPaths.EnumerateElfDlls(ct))
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    if (!File.Exists(path)) continue;
                    File.Delete(path);
                    EdrLog.Write(Name, "Removed ELF from browser: " + path, "ACTION", "simple_antivirus.log");
                    EdrState.ThreatCount++;
                }
                catch (Exception ex)
                {
                    if (EdrGlobalRules.QuarantineIfAllowed(path, "ELF", ct))
                        EdrLog.Write(Name, "ELF remove failed, quarantined: " + path + " | " + ex.Message, "WARNING", "simple_antivirus.log");
                }
            }

            int unsignedCount = 0;
            foreach (string basePath in EdrFile.GetSuspiciousScanPaths())
            {
                if (ct.IsCancellationRequested || unsignedCount >= MaxUnsignedPerRun) break;
                if (!Directory.Exists(basePath)) continue;
                try
                {
                    foreach (string e in Ext)
                    {
                        foreach (string f in Directory.GetFiles(basePath, "*" + e, SearchOption.TopDirectoryOnly))
                        {
                            if (ct.IsCancellationRequested || unsignedCount >= MaxUnsignedPerRun) break;
                            try
                            {
                                if (!File.Exists(f)) continue;
                                if (EdrWhitelist.IsWhitelistedPath(f)) continue;
                                if (EdrGlobalRules.QuarantineIfAllowed(f, "SimpleAntivirus", ct))
                                {
                                    EdrLog.Write(Name, "Malicious (API): " + f, "THREAT", "simple_antivirus.log");
                                    EdrState.ThreatCount++;
                                    unsignedCount++;
                                }
                            }
                            catch { }
                        }
                    }
                }
                catch { }
            }
        }
    }
}
