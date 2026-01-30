using System;
using System.Diagnostics;
using System.Threading;

namespace Edr
{
    public sealed class JobFirewallRuleMonitoring : IEdrJob
    {
        public string Name { get { return "FirewallRuleMonitoring"; } }
        public int IntervalSeconds { get { return 120; } }

        public void Run(CancellationToken ct)
        {
            try
            {
                var psi = new ProcessStartInfo { FileName = "netsh", Arguments = "advfirewall firewall show rule name=all", UseShellExecute = false, RedirectStandardOutput = true, CreateNoWindow = true };
                using (var p = Process.Start(psi))
                using (var r = p.StandardOutput)
                {
                    string o = r.ReadToEnd();
                    int n = 0; if (o != null) foreach (string line in o.Split('\n')) if (line.TrimStart().StartsWith("Rule Name:", StringComparison.OrdinalIgnoreCase)) n++;
                    EdrLog.Write(Name, "Firewall rules enumerated: " + n, "INFO", "firewall_monitoring.log");
                }
            }
            catch (Exception ex) { EdrLog.Write(Name, "Error: " + ex.Message, "ERROR", "firewall_monitoring.log"); }
        }
    }
}
