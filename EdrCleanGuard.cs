using System;
using System.IO;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace Edr
{
    public enum CleanGuardVerdict { Allow, KnownGood, Malicious }

    public static class EdrCleanGuard
    {
        /// <summary>Circl trust &gt;= this → auto-trust (Allow).</summary>
        public const int CirclTrustThreshold = 50;

        public static bool IsSystemPath(string path)
        {
            if (string.IsNullOrEmpty(path)) return true;
            string p = path.ToLowerInvariant().Replace('/', '\\');
            return p.IndexOf("\\windows\\", StringComparison.Ordinal) >= 0
                || p.IndexOf("\\program files\\", StringComparison.Ordinal) >= 0
                || p.IndexOf("program files (x86)", StringComparison.Ordinal) >= 0
                || p.IndexOf("\\windowsapps\\", StringComparison.Ordinal) >= 0;
        }

        /// <summary>Only Malicious when an API (MB/Cymru) says so. Auto-trust when Circl trust &gt;= threshold. Otherwise Allow — no quarantine/kill.</summary>
        public static CleanGuardVerdict Check(string path, string sha256, bool allowlisted, CancellationToken ct)
        {
            if (allowlisted) return CleanGuardVerdict.Allow;
            if (ct.IsCancellationRequested) return CleanGuardVerdict.Allow;

            string circlJson = null;
            try
            {
                string url = EdrConfig.CirclHashLookupUrl.TrimEnd('/') + "/" + sha256;
                circlJson = HttpGet(url);
            }
            catch { }
            // Circl KnownMalicious = 1 of 3 APIs reports malware
            if (circlJson != null && circlJson.IndexOf("\"KnownMalicious\"", StringComparison.OrdinalIgnoreCase) >= 0)
                return CleanGuardVerdict.Malicious;
            int circlTrust = -1;
            if (circlJson != null)
            {
                var m = Regex.Match(circlJson, @"[""']hashlookup:trust[""']\s*:\s*(\d+)", RegexOptions.IgnoreCase);
                if (m.Success) int.TryParse(m.Groups[1].Value, out circlTrust);
            }
            if (circlTrust >= CirclTrustThreshold) return CleanGuardVerdict.KnownGood;

            if (ct.IsCancellationRequested) return CleanGuardVerdict.Allow;
            // MalwareBazaar = 1 of 3 APIs reports malware
            try { if (MalwareBazaarHashFound(sha256)) return CleanGuardVerdict.Malicious; }
            catch { }

            if (ct.IsCancellationRequested) return CleanGuardVerdict.Allow;
            // Cymru = 1 of 3 APIs reports malware
            try { if (CymruMalicious(sha256)) return CleanGuardVerdict.Malicious; }
            catch { }

            return CleanGuardVerdict.Allow;
        }

        static string HttpGet(string url, int ms = 8000)
        {
            var req = (HttpWebRequest)WebRequest.Create(url);
            req.Method = "GET";
            req.Timeout = ms;
            req.ReadWriteTimeout = ms;
            req.UserAgent = "Edr/1.0";
            using (var resp = (HttpWebResponse)req.GetResponse())
            using (var rs = resp.GetResponseStream())
            using (var sr = new StreamReader(rs, Encoding.UTF8))
                return sr.ReadToEnd();
        }

        static bool MalwareBazaarHashFound(string sha256)
        {
            string json = "{\"query\":\"get_info\",\"hash\":\"" + sha256 + "\"}";
            var req = (HttpWebRequest)WebRequest.Create(EdrConfig.MalwareBazaarApiUrl);
            req.Method = "POST";
            req.ContentType = "application/json";
            req.Timeout = 12000;
            req.ReadWriteTimeout = 12000;
            req.UserAgent = "Edr/1.0";
            byte[] b = Encoding.UTF8.GetBytes(json);
            req.ContentLength = b.Length;
            using (var s = req.GetRequestStream()) s.Write(b, 0, b.Length);
            using (var resp = (HttpWebResponse)req.GetResponse())
            using (var rs = resp.GetResponseStream())
            using (var sr = new StreamReader(rs, Encoding.UTF8))
            {
                string body = sr.ReadToEnd();
                return body != null && body.IndexOf("\"hash_found\"", StringComparison.OrdinalIgnoreCase) >= 0;
            }
        }

        static bool CymruMalicious(string sha256)
        {
            string url = EdrConfig.CymruApiUrl.TrimEnd('/') + "/" + sha256;
            string body = HttpGet(url);
            return body != null && body.IndexOf("\"malware\":true", StringComparison.OrdinalIgnoreCase) >= 0;
        }
    }
}
