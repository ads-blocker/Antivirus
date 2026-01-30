using System;
using System.Net.NetworkInformation;
using System.Threading;

namespace Edr
{
    public sealed class JobBeaconDetection : IEdrJob
    {
        public string Name { get { return "BeaconDetection"; } }
        public int IntervalSeconds { get { return 60; } }

        static readonly int[] BeaconPorts = new[] { 4444, 5555, 6666, 8080, 443, 80 };

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
                    foreach (int port in BeaconPorts)
                    {
                        if (remotePort != port) continue;
                        EdrLog.Write(Name, "Potential beacon port " + port + " | " + (c.RemoteEndPoint != null ? c.RemoteEndPoint.ToString() : ""), "WARNING", "beacon_detections.log");
                        EdrState.ThreatCount++;
                        break;
                    }
                }
            }
            catch (Exception ex) { EdrLog.Write(Name, "Error: " + ex.Message, "ERROR", "beacon_detections.log"); }
        }
    }
}
