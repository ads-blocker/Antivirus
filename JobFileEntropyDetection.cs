using System;
using System.IO;
using System.Threading;

namespace Edr
{
    public sealed class JobFileEntropyDetection : IEdrJob
    {
        public string Name { get { return "FileEntropyDetection"; } }
        public int IntervalSeconds { get { return 120; } }

        public void Run(CancellationToken ct)
        {
            foreach (string basePath in EdrFile.GetSuspiciousScanPaths())
            {
                if (ct.IsCancellationRequested) break;
                if (!Directory.Exists(basePath)) continue;
                try
                {
                    foreach (string f in Directory.GetFiles(basePath, "*.exe", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) break;
                        try
                        {
                            double e = EdrFile.MeasureEntropy(f);
                            if (e > 7.5 && EdrFile.GetFileLength(f) < 1024 * 1024 * 5)
                                EdrLog.Write(Name, "High entropy: " + f + " | " + Math.Round(e, 2), "WARNING", "file_entropy_detections.log");
                        }
                        catch { }
                    }
                }
                catch { }
            }
        }
    }
}
