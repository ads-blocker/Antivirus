using System;
using System.Diagnostics;
using System.IO;
using Microsoft.Win32;

namespace Edr
{
    /// <summary>Optional install, persistence (HKCU Run), and uninstall for the EDR.</summary>
    public static class EdrInstall
    {
        public const string PersistenceValueName = "AntivirusProtection";
        const string RunKeyPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";

        public static string GetCurrentExePath()
        {
            try
            {
                string path = Process.GetCurrentProcess().MainModule != null ? Process.GetCurrentProcess().MainModule.FileName : null;
                if (!string.IsNullOrEmpty(path) && File.Exists(path)) return path;
            }
            catch { }
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            string fallback = Path.Combine(baseDir, "Antivirus.exe");
            return File.Exists(fallback) ? fallback : (baseDir ?? "");
        }

        public static string GetInstalledExePath()
        {
            return Path.Combine(EdrConfig.InstallPath, "Antivirus.exe");
        }

        public static bool IsInstalled()
        {
            string exe = GetInstalledExePath();
            return File.Exists(exe);
        }

        /// <summary>Install: create dirs, copy exe (+ yara.exe, rules.yar) to InstallPath.</summary>
        public static string Install()
        {
            string src = GetCurrentExePath();
            if (string.IsNullOrEmpty(src) || !File.Exists(src))
                return "Current executable not found.";
            try
            {
                if (!Directory.Exists(EdrConfig.InstallPath))
                    Directory.CreateDirectory(EdrConfig.InstallPath);
                foreach (string sub in new[] { "Logs", "Quarantine", "Reports", "Data", EdrConfig.YaraSubFolder })
                {
                    string d = Path.Combine(EdrConfig.InstallPath, sub);
                    if (!Directory.Exists(d)) Directory.CreateDirectory(d);
                }
                string dest = GetInstalledExePath();
                File.Copy(src, dest, true);
                string baseDir = Path.GetDirectoryName(src) ?? "";
                string yaraSrc = Path.Combine(baseDir, EdrConfig.YaraExeName);
                if (File.Exists(yaraSrc))
                {
                    string yaraDest = Path.Combine(EdrConfig.InstallPath, EdrConfig.YaraSubFolder, EdrConfig.YaraExeName);
                    string yaraDir = Path.GetDirectoryName(yaraDest);
                    if (!Directory.Exists(yaraDir)) Directory.CreateDirectory(yaraDir);
                    File.Copy(yaraSrc, yaraDest, true);
                }
                string rulesSrc = Path.Combine(baseDir, EdrConfig.YaraRulesFileName);
                if (File.Exists(rulesSrc))
                {
                    string rulesDest = Path.Combine(EdrConfig.InstallPath, EdrConfig.YaraRulesFileName);
                    File.Copy(rulesSrc, rulesDest, true);
                }
                EdrLog.Write("EdrInstall", "Installed to " + EdrConfig.InstallPath, "INFO");
                return null;
            }
            catch (Exception ex)
            {
                EdrLog.Write("EdrInstall", "Install failed: " + ex.Message, "ERROR");
                return "Install failed: " + ex.Message;
            }
        }

        public static bool IsPersisted()
        {
            try
            {
                using (var k = Registry.CurrentUser.OpenSubKey(RunKeyPath))
                {
                    if (k == null) return false;
                    object v = k.GetValue(PersistenceValueName);
                    return v != null && !string.IsNullOrEmpty(v.ToString());
                }
            }
            catch { return false; }
        }

        /// <summary>Enable persistence via HKCU Run. Installs first if not installed.</summary>
        public static string EnablePersistence()
        {
            if (!IsInstalled())
            {
                string err = Install();
                if (err != null) return err;
            }
            string exe = GetInstalledExePath();
            try
            {
                using (var k = Registry.CurrentUser.CreateSubKey(RunKeyPath))
                {
                    if (k == null) return "Could not open Run key.";
                    k.SetValue(PersistenceValueName, "\"" + exe + "\"");
                }
                EdrLog.Write("EdrInstall", "Persistence enabled (HKCU Run).", "INFO");
                return null;
            }
            catch (Exception ex)
            {
                EdrLog.Write("EdrInstall", "Enable persistence failed: " + ex.Message, "ERROR");
                return "Persistence enable failed: " + ex.Message;
            }
        }

        public static string DisablePersistence()
        {
            try
            {
                using (var k = Registry.CurrentUser.OpenSubKey(RunKeyPath, true))
                {
                    if (k != null) k.DeleteValue(PersistenceValueName, false);
                }
                EdrLog.Write("EdrInstall", "Persistence disabled (HKCU Run removed).", "INFO");
                return null;
            }
            catch (Exception ex)
            {
                EdrLog.Write("EdrInstall", "Disable persistence failed: " + ex.Message, "ERROR");
                return "Persistence disable failed: " + ex.Message;
            }
        }

        /// <summary>Uninstall: remove persistence, then delete InstallPath. Fails if exe in use.</summary>
        public static string Uninstall()
        {
            DisablePersistence();
            try
            {
                if (Directory.Exists(EdrConfig.InstallPath))
                    Directory.Delete(EdrConfig.InstallPath, true);
                return null;
            }
            catch (Exception ex)
            {
                try { EdrLog.Write("EdrInstall", "Uninstall delete failed: " + ex.Message, "ERROR"); } catch { }
                return "Uninstall failed (folder in use?): " + ex.Message;
            }
        }
    }
}
