using System;
using System.Diagnostics;
using System.Threading;

namespace Edr
{
    public sealed class JobShadowCopyMonitoring : IEdrJob
    {
        public string Name { get { return "ShadowCopyMonitoring"; } }
        public int IntervalSeconds { get { return 30; } }

        public void Run(CancellationToken ct)
        {
            try
            {
                var psi = new ProcessStartInfo { FileName = "vssadmin", Arguments = "list shadows", UseShellExecute = false, RedirectStandardOutput = true, CreateNoWindow = true };
                using (var p = Process.Start(psi))
                using (var r = p.StandardOutput)
                {
                    string out_ = r.ReadToEnd();
                    if (out_ != null && out_.IndexOf("No items found", StringComparison.OrdinalIgnoreCase) >= 0)
                        EdrLog.Write(Name, "No shadow copies found (potential deletion attempt)", "WARNING", "shadow_copy.log");
                    else
                        EdrLog.Write(Name, "Shadow copy check completed", "INFO", "shadow_copy.log");
                }
            }
            catch (Exception ex) { EdrLog.Write(Name, "Error: " + ex.Message, "ERROR", "shadow_copy.log"); }
        }
    }
}
