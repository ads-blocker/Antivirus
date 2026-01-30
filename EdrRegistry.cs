using System;
using System.Collections.Generic;
using Microsoft.Win32;

namespace Edr
{
    public static class EdrRegistry
    {
        public struct RunEntry
        {
            public string KeyName;
            public string ValueName;
            public string Value;
        }

        static readonly string[] RunKeys = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        };

        public static List<RunEntry> GetRunEntries(bool localMachine, bool currentUser)
        {
            var list = new List<RunEntry>();
            try
            {
                if (localMachine)
                {
                    using (var baseKey = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"))
                    {
                        if (baseKey != null) AddValues(list, baseKey, "HKLM\\...\\Run");
                    }
                    using (var baseKey = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"))
                    {
                        if (baseKey != null) AddValues(list, baseKey, "HKLM\\...\\RunOnce");
                    }
                }
                if (currentUser)
                {
                    using (var baseKey = Registry.CurrentUser.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"))
                    {
                        if (baseKey != null) AddValues(list, baseKey, "HKCU\\...\\Run");
                    }
                    using (var baseKey = Registry.CurrentUser.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"))
                    {
                        if (baseKey != null) AddValues(list, baseKey, "HKCU\\...\\RunOnce");
                    }
                }
            }
            catch (Exception ex) { EdrLog.Write("EdrRegistry", "GetRunEntries error: " + ex.Message, "ERROR"); }
            return list;
        }

        static void AddValues(List<RunEntry> list, RegistryKey key, string keyName)
        {
            foreach (string name in key.GetValueNames())
            {
                try
                {
                    object v = key.GetValue(name);
                    string val = v != null ? v.ToString() : "";
                    list.Add(new RunEntry { KeyName = keyName, ValueName = name, Value = val });
                }
                catch { }
            }
        }

        public static bool IsAmsiDisabled()
        {
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\AMSI"))
                {
                    if (k == null) return false;
                    object v = k.GetValue("DisableAMSI");
                    if (v == null) return false;
                    int i; if (int.TryParse(v.ToString(), out i)) return i != 0;
                    return string.Equals(v.ToString(), "1", StringComparison.OrdinalIgnoreCase);
                }
            }
            catch { return false; }
        }
    }
}
