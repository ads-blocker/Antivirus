using System;
using System.IO;

namespace Edr
{
    /// <summary>Whitelist for paths/process names never to flag or quarantine (e.g. explorer.exe).</summary>
    public static class EdrWhitelist
    {
        static readonly string[] AllowedNames = new[]
        {
            "explorer.exe",
            "explorer",
            "Antivirus.exe",
            "dllhost.exe",
            "conhost.exe",
            "sihost.exe",
            "fontdrvhost.exe",
            "SearchHost.exe",
            "RuntimeBroker.exe",
            "StartMenuExperienceHost.exe",
            "SystemSettings.exe",
            "ApplicationFrameHost.exe",
            "Taskmgr.exe",
            "msiexec.exe",
            "TrustedInstaller.exe"
        };

        public static bool IsWhitelistedPath(string path)
        {
            if (string.IsNullOrEmpty(path)) return true;
            string name = Path.GetFileName(path);
            if (string.IsNullOrEmpty(name)) return false;
            foreach (string n in AllowedNames)
            {
                if (string.Equals(name, n, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }
    }
}
