using System;
using System.Net.NetworkInformation;
using System.Threading;

namespace Edr
{
    public sealed class JobDNSExfiltrationDetection : IEdrJob
    {
        public string Name { get { return "DNSExfiltrationDetection"; } }
        public int IntervalSeconds { get { return 90; } }

        public void Run(CancellationToken ct)
        {
            try
            {
                var stats = IPGlobalProperties.GetIPGlobalProperties().GetUdpIPv4Statistics();
                EdrLog.Write(Name, "UDP stats (DNS proxy): Received " + stats.DatagramsReceived + " Sent " + stats.DatagramsSent, "INFO", "dns_exfiltration.log");
            }
            catch (Exception ex) { EdrLog.Write(Name, "Error: " + ex.Message, "ERROR", "dns_exfiltration.log"); }
        }
    }
}
