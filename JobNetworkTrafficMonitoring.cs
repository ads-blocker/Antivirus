using System;
using System.Net.NetworkInformation;
using System.Threading;

namespace Edr
{
    public sealed class JobNetworkTrafficMonitoring : IEdrJob
    {
        public string Name { get { return "NetworkTrafficMonitoring"; } }
        public int IntervalSeconds { get { return 45; } }

        public void Run(CancellationToken ct)
        {
            try
            {
                var props = IPGlobalProperties.GetIPGlobalProperties();
                int listeners = props.GetActiveTcpListeners().Length;
                int conns = props.GetActiveTcpConnections().Length;
                EdrLog.Write(Name, "Listeners: " + listeners + " | TCP connections: " + conns, "INFO", "network_traffic.log");
            }
            catch (Exception ex) { EdrLog.Write(Name, "Error: " + ex.Message, "ERROR", "network_traffic.log"); }
        }
    }
}
