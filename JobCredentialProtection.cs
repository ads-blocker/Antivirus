using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using Microsoft.Win32;

namespace Edr
{
    /// <summary>
    /// Hardens credential storage: LSASS RunAsPPL, clear cached credentials, disable credential caching, enable credential validation auditing.
    /// </summary>
    public sealed class JobCredentialProtection : IEdrJob
    {
        public string Name { get { return "CredentialProtection"; } }
        public int IntervalSeconds { get { return 300; } }

        const string PasswordTaskName = "GenerateRandomPassword";
        const string PasswordScriptName = "PasswordTasks.ps1";

        public void Run(CancellationToken ct)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                ProtectCredentials(ct);
                RemovePasswordTaskIfPresent(ct);
            }
            catch (Exception ex)
            {
                EdrLog.Write(Name, "Credential protection error: " + ex.Message, "ERROR", "credential_protection.log");
            }
        }

        /// <summary>Remove legacy random-password task and script if present (no longer used).</summary>
        static void RemovePasswordTaskIfPresent(CancellationToken ct)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "schtasks",
                    Arguments = "/delete /tn \"" + PasswordTaskName + "\" /f",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using (var p = Process.Start(psi))
                { if (p != null) p.WaitForExit(3000); }
            }
            catch { }
            if (ct.IsCancellationRequested) return;
            try
            {
                string scriptPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), PasswordScriptName);
                if (File.Exists(scriptPath))
                    File.Delete(scriptPath);
            }
            catch { }
        }

        static void ProtectCredentials(CancellationToken ct)
        {
            try
            {
                // LSASS as Protected Process Light (reboot required to take effect)
                using (var key = Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Control\Lsa", false))
                {
                    if (key != null)
                    {
                        key.SetValue("RunAsPPL", 1, RegistryValueKind.DWord);
                        EdrLog.Write("CredentialProtection", "Enabled LSASS as Protected Process Light. Reboot required.", "INFO", "credential_protection.log");
                    }
                }
            }
            catch (Exception ex)
            {
                EdrLog.Write("CredentialProtection", "RunAsPPL: " + ex.Message, "ERROR", "credential_protection.log");
            }

            if (ct.IsCancellationRequested) return;

            // Clear cached credentials via cmdkey
            string cmdkeyPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmdkey.exe");
            if (File.Exists(cmdkeyPath))
            {
                try
                {
                    var psiList = new ProcessStartInfo
                    {
                        FileName = cmdkeyPath,
                        Arguments = "/list",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    };
                    using (var p = Process.Start(psiList))
                    {
                        if (p != null)
                        {
                            string output = p.StandardOutput.ReadToEnd();
                            p.WaitForExit(5000);
                            if (!string.IsNullOrEmpty(output))
                            {
                                foreach (string line in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                                {
                                    if (ct.IsCancellationRequested) break;
                                    string trimmed = line.Trim();
                                    if (trimmed.StartsWith("Target:", StringComparison.OrdinalIgnoreCase))
                                    {
                                        string target = trimmed.Substring(7).Trim();
                                        if (string.IsNullOrEmpty(target)) continue;
                                        try
                                        {
                                            var psiDel = new ProcessStartInfo
                                            {
                                                FileName = cmdkeyPath,
                                                Arguments = "/delete:" + target,
                                                UseShellExecute = false,
                                                CreateNoWindow = true
                                            };
                                            using (var pd = Process.Start(psiDel))
                                            { if (pd != null) pd.WaitForExit(3000); }
                                        }
                                        catch { }
                                    }
                                }
                                EdrLog.Write("CredentialProtection", "Cleared cached credentials.", "INFO", "credential_protection.log");
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    EdrLog.Write("CredentialProtection", "cmdkey: " + ex.Message, "ERROR", "credential_protection.log");
                }
            }

            if (ct.IsCancellationRequested) return;

            try
            {
                // Disable credential caching
                using (var key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", false))
                {
                    if (key != null)
                    {
                        key.SetValue("CachedLogonsCount", "0", RegistryValueKind.String);
                        EdrLog.Write("CredentialProtection", "Disabled credential caching.", "INFO", "credential_protection.log");
                    }
                }
            }
            catch (Exception ex)
            {
                EdrLog.Write("CredentialProtection", "CachedLogonsCount: " + ex.Message, "ERROR", "credential_protection.log");
            }

            if (ct.IsCancellationRequested) return;

            // Enable auditing for credential validation
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "auditpol",
                    Arguments = "/set /subcategory:\"Credential Validation\" /success:enable /failure:enable",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using (var p = Process.Start(psi))
                { if (p != null) p.WaitForExit(5000); }
                EdrLog.Write("CredentialProtection", "Enabled auditing for credential validation.", "INFO", "credential_protection.log");
            }
            catch (Exception ex)
            {
                EdrLog.Write("CredentialProtection", "auditpol: " + ex.Message, "ERROR", "credential_protection.log");
            }
        }

        /// <summary>Revert credential protection changes that cause persistent system slowness. Run as admin.</summary>
        public static void RevertCredentialProtection()
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Lsa", true))
                { if (key != null) key.SetValue("RunAsPPL", 0, RegistryValueKind.DWord); }
            }
            catch { }
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", true))
                { if (key != null) key.SetValue("CachedLogonsCount", "10", RegistryValueKind.String); }
            }
            catch { }
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "auditpol",
                    Arguments = "/set /subcategory:\"Credential Validation\" /success:disable /failure:disable",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using (var p = Process.Start(psi))
                { if (p != null) p.WaitForExit(5000); }
            }
            catch { }
        }
    }
}
