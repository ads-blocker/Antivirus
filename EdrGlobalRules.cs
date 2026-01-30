using System;
using System.Diagnostics;
using System.IO;
using System.Threading;

namespace Edr
{
    /// <summary>Global kill/quarantine rules using CleanGuard (only act when APIs report malicious; auto-trust via Circl).</summary>
    public static class EdrGlobalRules
    {
        static string _selfHash;

        static string SelfHash()
        {
            if (_selfHash != null) return _selfHash;
            try
            {
                string self = Process.GetCurrentProcess().MainModule != null ? Process.GetCurrentProcess().MainModule.FileName : null;
                if (!string.IsNullOrEmpty(self) && File.Exists(self))
                    _selfHash = EdrFile.ComputeSha256(self);
            }
            catch { }
            return _selfHash;
        }

        /// <summary>True only when CleanGuard says Malicious (and not whitelisted / self).</summary>
        public static bool ShouldQuarantine(string path, CancellationToken ct, string sha256 = null)
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return false;
            if (EdrWhitelist.IsWhitelistedPath(path)) return false;
            string hash = sha256 ?? EdrFile.ComputeSha256(path);
            if (string.IsNullOrEmpty(hash)) return false;
            string sh = SelfHash();
            bool allowlisted = sh != null && string.Equals(hash, sh, StringComparison.OrdinalIgnoreCase);
            if (allowlisted) return false;
            var v = EdrCleanGuard.Check(path, hash, false, ct);
            return v == CleanGuardVerdict.Malicious;
        }

        /// <summary>True only when CleanGuard says Malicious for the process exe (and not whitelisted / self).</summary>
        public static bool ShouldKill(int processId, string processName, string exePath, CancellationToken ct)
        {
            if (processId == EdrProcess.CurrentPid) return false;
            string path = !string.IsNullOrEmpty(exePath) ? exePath : EdrProcess.GetExecutablePath(processId);
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return false;
            if (EdrWhitelist.IsWhitelistedPath(path)) return false;
            string hash = EdrFile.ComputeSha256(path);
            if (string.IsNullOrEmpty(hash)) return false;
            string sh = SelfHash();
            if (sh != null && string.Equals(hash, sh, StringComparison.OrdinalIgnoreCase)) return false;
            var v = EdrCleanGuard.Check(path, hash, false, ct);
            return v == CleanGuardVerdict.Malicious;
        }

        static bool AllowQuarantine() { return EdrConfig.AutoQuarantine; }
        static bool AllowKill() { return EdrConfig.AutoKillThreats; }

        /// <summary>Quarantine only if CleanGuard allows (Malicious) and AutoQuarantine is on. Returns true if quarantined.</summary>
        public static bool QuarantineIfAllowed(string path, string reason, CancellationToken ct)
        {
            if (!AllowQuarantine()) return false;
            if (!ShouldQuarantine(path, ct)) return false;
            return EdrQuarantine.MoveToQuarantine(path, reason);
        }

        /// <summary>Kill only if CleanGuard allows (Malicious) and AutoKillThreats is on.</summary>
        public static void KillIfAllowed(int processId, string processName, string exePath, CancellationToken ct)
        {
            if (!AllowKill()) return;
            if (!ShouldKill(processId, processName, exePath, ct)) return;
            EdrProcess.KillThreat(processId, processName);
        }
    }
}
