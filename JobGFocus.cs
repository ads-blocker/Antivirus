using System;
using System.Net.NetworkInformation;
using System.Threading;

namespace Edr
{
    public sealed class JobGFocus : IEdrJob
    {
        public string Name { get { return "GFocus"; } }
        public int IntervalSeconds { get { return 30; } }

        public void Run(CancellationToken ct)
        {
            try
            {
                var conns = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections();
                int est = 0;
                foreach (var c in conns)
                {
                    if (ct.IsCancellationRequested) break;
                    if (c.State != TcpState.Established) continue;
                    est++;
                }
                EdrLog.Write(Name, "Established TCP connections: " + est, "INFO", "gfocus.log");
            }
            catch (Exception ex) { EdrLog.Write(Name, "Error: " + ex.Message, "ERROR", "gfocus.log"); }
        }
    }
}
