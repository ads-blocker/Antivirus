using System;
using System.Collections.Generic;
using System.IO;

namespace Edr
{
    public static class EdrBrowserPaths
    {
        public static IEnumerable<string> GetBrowserRoots()
        {
            var list = new List<string>();
            string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string app = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            if (string.IsNullOrEmpty(local)) local = Environment.GetEnvironmentVariable("LOCALAPPDATA") ?? "";
            if (string.IsNullOrEmpty(app)) app = Environment.GetEnvironmentVariable("APPDATA") ?? "";

            var entries = new[]
            {
                Path.Combine(local, "Google", "Chrome", "User Data"),
                Path.Combine(local, "Microsoft", "Edge", "User Data"),
                Path.Combine(local, "BraveSoftware", "Brave-Browser", "User Data"),
                Path.Combine(local, "Opera Software", "Opera Stable"),
                Path.Combine(local, "Opera Software", "Opera GX Stable"),
                Path.Combine(local, "Vivaldi", "User Data"),
                Path.Combine(local, "Yandex", "YandexBrowser", "User Data"),
                Path.Combine(app, "Mozilla", "Firefox", "Profiles"),
                Path.Combine(local, "Mozilla", "Firefox", "Profiles"),
                Path.Combine(local, "Opera Software", "Opera Neon", "User Data"),
                Path.Combine(local, "Chromium", "User Data"),
                Path.Combine(local, "Slimjet", "User Data"),
                Path.Combine(local, "CocCoc", "Browser", "User Data"),
                Path.Combine(local, "360Browser", "Browser", "User Data"),
                Path.Combine(local, "TorBrowser", "Data", "Browser"),
            };

            foreach (string p in entries)
            {
                if (string.IsNullOrEmpty(p) || !Directory.Exists(p)) continue;
                list.Add(p);
            }
            return list;
        }

        public static IEnumerable<string> EnumerateElfDlls(System.Threading.CancellationToken ct)
        {
            var out_ = new List<string>();
            foreach (string root in GetBrowserRoots())
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    foreach (string f in Directory.GetFiles(root, "*_elf.dll", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) break;
                        out_.Add(f);
                    }
                }
                catch { }
            }
            return out_;
        }
    }
}
