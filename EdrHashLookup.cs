using System;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;

namespace Edr
{
    public sealed class HashReputation
    {
        public bool IsMalicious;
        public int Confidence;
        public string Sources;
    }

    public static class EdrHashLookup
    {
        public static HashReputation Lookup(string sha256, CancellationToken ct)
        {
            var r = new HashReputation { IsMalicious = false, Confidence = 0, Sources = "" };
            var sources = new System.Collections.Generic.List<string>();

            if (ct.IsCancellationRequested) return r;

            try
            {
                string circl = CirclLookup(sha256);
                if (circl != null && circl.IndexOf("\"KnownMalicious\"", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    r.IsMalicious = true;
                    r.Confidence += 40;
                    sources.Add("CIRCL");
                }
            }
            catch { }

            if (ct.IsCancellationRequested) return r;
            try
            {
                if (MalwareBazaarLookup(sha256)) { r.IsMalicious = true; r.Confidence += 50; sources.Add("MalwareBazaar"); }
            }
            catch { }

            if (ct.IsCancellationRequested) return r;
            try
            {
                if (CymruLookup(sha256)) { r.IsMalicious = true; r.Confidence += 30; sources.Add("Cymru"); }
            }
            catch { }

            r.Sources = string.Join(", ", sources);
            return r;
        }

        static string HttpGet(string url, int timeoutMs = 5000)
        {
            var req = (HttpWebRequest)WebRequest.Create(url);
            req.Method = "GET";
            req.Timeout = timeoutMs;
            req.ReadWriteTimeout = timeoutMs;
            req.UserAgent = "Edr/1.0";
            using (var resp = (HttpWebResponse)req.GetResponse())
            using (var rs = resp.GetResponseStream())
            using (var sr = new StreamReader(rs, Encoding.UTF8))
                return sr.ReadToEnd();
        }

        static string HttpPost(string url, string json, int timeoutMs = 5000)
        {
            var req = (HttpWebRequest)WebRequest.Create(url);
            req.Method = "POST";
            req.ContentType = "application/json";
            req.Timeout = timeoutMs;
            req.ReadWriteTimeout = timeoutMs;
            req.UserAgent = "Edr/1.0";
            byte[] b = Encoding.UTF8.GetBytes(json);
            req.ContentLength = b.Length;
            using (var s = req.GetRequestStream()) s.Write(b, 0, b.Length);
            using (var resp = (HttpWebResponse)req.GetResponse())
            using (var rs = resp.GetResponseStream())
            using (var sr = new StreamReader(rs, Encoding.UTF8))
                return sr.ReadToEnd();
        }

        static string CirclLookup(string sha256)
        {
            string url = EdrConfig.CirclHashLookupUrl.TrimEnd('/') + "/" + sha256;
            return HttpGet(url);
        }

        static bool MalwareBazaarLookup(string sha256)
        {
            string json = "{\"query\":\"get_info\",\"hash\":\"" + sha256 + "\"}";
            string body = HttpPost(EdrConfig.MalwareBazaarApiUrl, json);
            return body != null && body.IndexOf("\"hash_found\"", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        static bool CymruLookup(string sha256)
        {
            string url = EdrConfig.CymruApiUrl.TrimEnd('/') + "/" + sha256;
            string body = HttpGet(url);
            return body != null && body.IndexOf("\"malware\":true", StringComparison.OrdinalIgnoreCase) >= 0;
        }
    }
}
