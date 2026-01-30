using System;
using System.Collections.Generic;
using System.Management;

namespace Edr
{
    public static class EdrWmi
    {
        public struct WmiFilter { public string Name; public string Query; }
        public struct WmiConsumer { public string Name; public string CommandLineTemplate; }

        public static List<WmiFilter> GetEventFilters()
        {
            var list = new List<WmiFilter>();
            try
            {
                using (var searcher = new ManagementObjectSearcher("root\\subscription", "SELECT * FROM __EventFilter"))
                using (var results = searcher.Get())
                {
                    foreach (ManagementBaseObject o in results)
                    {
                        var mo = (ManagementObject)o;
                        list.Add(new WmiFilter
                        {
                            Name = mo["Name"] != null ? mo["Name"].ToString() : "",
                            Query = mo["Query"] != null ? mo["Query"].ToString() : ""
                        });
                    }
                }
            }
            catch (Exception ex) { EdrLog.Write("EdrWmi", "GetEventFilters error: " + ex.Message, "ERROR"); }
            return list;
        }

        public static List<WmiConsumer> GetCommandLineConsumers()
        {
            var list = new List<WmiConsumer>();
            try
            {
                using (var searcher = new ManagementObjectSearcher("root\\subscription", "SELECT * FROM CommandLineEventConsumer"))
                using (var results = searcher.Get())
                {
                    foreach (ManagementBaseObject o in results)
                    {
                        var mo = (ManagementObject)o;
                        list.Add(new WmiConsumer
                        {
                            Name = mo["Name"] != null ? mo["Name"].ToString() : "",
                            CommandLineTemplate = mo["CommandLineTemplate"] != null ? mo["CommandLineTemplate"].ToString() : ""
                        });
                    }
                }
            }
            catch (Exception ex) { EdrLog.Write("EdrWmi", "GetCommandLineConsumers error: " + ex.Message, "ERROR"); }
            return list;
        }
    }
}
