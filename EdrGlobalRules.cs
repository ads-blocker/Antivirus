using System;
using System.Diagnostics;
using System.IO;
using System.Threading;

namespace Edr
{
    /// <summary>Layered threat response: kill/quarantine only when ≥1 of 3 APIs (Circl, MalwareBazaar, Cymru) report malicious; behavioral threats use threat level.</summary>
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

        /// <summary>True only when ≥1 of 3 APIs report Malicious (and not whitelisted / self).</summary>
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

        /// <summary>True only when ≥1 of 3 APIs report Malicious for the process exe (and not whitelisted / self).</summary>
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
        static bool AllowBlock() { return EdrConfig.AutoBlockThreats; }

        /// <summary>Quarantine only if ≥1 API reports Malicious and AutoQuarantine is on. Returns true if quarantined.</summary>
        public static bool QuarantineIfAllowed(string path, string reason, CancellationToken ct)
        {
            if (!AllowQuarantine()) return false;
            if (!ShouldQuarantine(path, ct)) return false;
            return EdrQuarantine.MoveToQuarantine(path, reason);
        }

        /// <summary>Kill only if ≥1 API reports Malicious and AutoKillThreats is on.</summary>
        public static void KillIfAllowed(int processId, string processName, string exePath, CancellationToken ct)
        {
            if (!AllowKill()) return;
            if (!ShouldKill(processId, processName, exePath, ct)) return;
            EdrProcess.KillThreat(processId, processName);
        }

        /// <summary>Layered behavioral response (fileless, LOLBin, AMSI bypass, etc.). No API check—host exe is trusted; threat is in behavior. Low=log; Medium=suspend (block); High/Critical=kill.</summary>
        public static void RespondToBehavioralThreat(int processId, string processName, string exePath, ThreatLevel level)
        {
            if (processId == EdrProcess.CurrentPid) return;
            string path = !string.IsNullOrEmpty(exePath) ? exePath : EdrProcess.GetExecutablePath(processId);
            if (!string.IsNullOrEmpty(path) && EdrWhitelist.IsWhitelistedPath(path)) return;

            switch (level)
            {
                case ThreatLevel.Low:
                    break; // Log only (caller already logged)
                case ThreatLevel.Medium:
                    if (AllowBlock()) EdrProcess.SuspendThreat(processId, processName);
                    break;
                case ThreatLevel.High:
                case ThreatLevel.Critical:
                    if (AllowKill()) EdrProcess.KillThreat(processId, processName);
                    break;
            }
        }
    }
}
