using System;
using System.Net.NetworkInformation;
using System.Threading;

namespace Edr
{
    public sealed class JobNetworkAnomalyDetection : IEdrJob
    {
        public string Name { get { return "NetworkAnomalyDetection"; } }
        public int IntervalSeconds { get { return 90; } }

        static readonly int[] SuspiciousPorts = new[] { 4444, 5555, 6666, 8080, 31337, 12345 };

        public void Run(CancellationToken ct)
        {
            try
            {
                var conns = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections();
                foreach (var c in conns)
                {
                    if (ct.IsCancellationRequested) break;
                    if (c.State != TcpState.Established) continue;
                    int remotePort = c.RemoteEndPoint != null ? c.RemoteEndPoint.Port : 0;
                    foreach (int port in SuspiciousPorts)
                    {
                        if (remotePort != port) continue;
                        EdrLog.Write(Name, "Suspicious remote port " + port + " | Local: " + (c.LocalEndPoint != null ? c.LocalEndPoint.ToString() : "") + " -> " + (c.RemoteEndPoint != null ? c.RemoteEndPoint.ToString() : ""), "WARNING", "network_anomaly.log");
                        EdrState.ThreatCount++;
                        break;
                    }
                }
            }
            catch (Exception ex) { EdrLog.Write(Name, "Error: " + ex.Message, "ERROR", "network_anomaly.log"); }
        }
    }
}
