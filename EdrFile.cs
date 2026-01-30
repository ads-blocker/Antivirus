using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Threading;

namespace Edr
{
    public static class EdrFile
    {
        static readonly string[] SuspiciousExtensions = { ".exe", ".dll", ".scr", ".vbs", ".ps1", ".bat", ".cmd" };
        const long OneMb = 1024 * 1024;

        public static string[] GetSuspiciousScanPaths()
        {
            var localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var userProfile = Environment.GetEnvironmentVariable("USERPROFILE") ?? "";
            var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            return new[]
            {
                Path.GetTempPath(),
                appData,
                Path.Combine(localApp, "Temp"),
                Path.Combine(win, "Temp"),
                Path.Combine(userProfile, "Downloads")
            };
        }

        public static List<string> EnumerateSuspiciousFiles(CancellationToken ct)
        {
            var list = new List<string>();
            foreach (string basePath in GetSuspiciousScanPaths())
            {
                if (ct.IsCancellationRequested) break;
                if (string.IsNullOrEmpty(basePath) || !Directory.Exists(basePath)) continue;
                try
                {
                    foreach (string ext in SuspiciousExtensions)
                    {
                        foreach (string f in Directory.GetFiles(basePath, "*" + ext, SearchOption.AllDirectories))
                        {
                            if (ct.IsCancellationRequested) break;
                            try { list.Add(f); } catch { }
                        }
                    }
                }
                catch { }
            }
            return list;
        }

        public static string ComputeSha256(string path)
        {
            try
            {
                using (var sha = SHA256.Create())
                using (var fs = File.OpenRead(path))
                {
                    byte[] hash = sha.ComputeHash(fs);
                    return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                }
            }
            catch { return null; }
        }

        public static double MeasureEntropy(string path)
        {
            try
            {
                byte[] bytes;
                using (var fs = File.OpenRead(path))
                {
                    int toRead = (int)Math.Min(4097, fs.Length);
                    bytes = new byte[toRead];
                    int r = fs.Read(bytes, 0, toRead);
                    if (r <= 0) return 0;
                    if (r < bytes.Length) Array.Resize(ref bytes, r);
                }
                var freq = new Dictionary<byte, int>();
                foreach (byte b in bytes)
                {
                    if (!freq.ContainsKey(b)) freq[b] = 0;
                    freq[b]++;
                }
                double ent = 0;
                double n = bytes.Length;
                foreach (int c in freq.Values)
                {
                    double p = c / n;
                    ent -= p * Math.Log(p, 2);
                }
                return ent;
            }
            catch { return 0; }
        }

        public static long GetFileLength(string path)
        {
            try { return new FileInfo(path).Length; } catch { return 0; }
        }

        public static bool IsSuspiciousDllPath(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            string p = path.ToUpperInvariant();
            if (p.IndexOf("\\TEMP\\", StringComparison.Ordinal) >= 0 || p.IndexOf("\\TEMP\"", StringComparison.Ordinal) >= 0) return true;
            if (p.IndexOf("\\APPDATA\\", StringComparison.Ordinal) >= 0) return true;
            if (p.IndexOf("\\LOCALAPPDATA\\", StringComparison.Ordinal) >= 0) return true;
            if (p.IndexOf("\\DOWNLOAD", StringComparison.Ordinal) >= 0) return true;
            if (p.IndexOf("\\DESKTOP", StringComparison.Ordinal) >= 0) return true;
            return false;
        }
    }
}
