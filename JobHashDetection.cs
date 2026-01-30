using System;
using System.IO;
using System.Threading;

namespace Edr
{
    public sealed class JobHashDetection : IEdrJob
    {
        public string Name { get { return "HashDetection"; } }
        public int IntervalSeconds { get { return 15; } }

        public void Run(CancellationToken ct)
        {
            var files = EdrFile.EnumerateSuspiciousFiles(ct);
            foreach (string path in files)
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    if (EdrWhitelist.IsWhitelistedPath(path)) continue;
                    if (EdrGlobalRules.QuarantineIfAllowed(path, "HashDetection", ct))
                    {
                        string hash = EdrFile.ComputeSha256(path);
                        EdrLog.Write(Name, "THREAT (CleanGuard): " + path + (string.IsNullOrEmpty(hash) ? "" : " | Hash: " + hash), "THREAT", "hash_detections.log");
                        EdrState.ThreatCount++;
                    }
                    else
                    {
                        double ent = EdrFile.MeasureEntropy(path);
                        long len = EdrFile.GetFileLength(path);
                        if (ent > 7.5 && len > 0 && len < 1024 * 1024)
                            EdrLog.Write(Name, "High entropy: " + path + " | Entropy: " + Math.Round(ent, 2), "WARNING", "hash_detections.log");
                    }
                }
                catch (Exception ex) { EdrLog.Write(Name, "Error scanning " + path + ": " + ex.Message, "ERROR", "hash_detections.log"); }
            }
        }
    }
}
