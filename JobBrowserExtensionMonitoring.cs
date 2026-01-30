using System;
using System.IO;
using System.Threading;

namespace Edr
{
    public sealed class JobBrowserExtensionMonitoring : IEdrJob
    {
        public string Name { get { return "BrowserExtensionMonitoring"; } }
        public int IntervalSeconds { get { return 300; } }

        public void Run(CancellationToken ct)
        {
            try
            {
                string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                string[] paths = new[]
                {
                    Path.Combine(local, "Google", "Chrome", "User Data", "Default", "Extensions"),
                    Path.Combine(local, "Microsoft", "Edge", "User Data", "Default", "Extensions")
                };
                foreach (string p in paths)
                {
                    if (ct.IsCancellationRequested) break;
                    if (!Directory.Exists(p)) continue;
                    int n = 0;
                    foreach (string d in Directory.GetDirectories(p)) { n++; }
                    EdrLog.Write(Name, "Extensions folder " + p + ": " + n + " extension(s)", "INFO", "browser_extension.log");
                }
            }
            catch (Exception ex) { EdrLog.Write(Name, "Error: " + ex.Message, "ERROR", "browser_extension.log"); }
        }
    }
}
