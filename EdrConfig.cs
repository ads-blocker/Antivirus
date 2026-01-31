namespace Edr
{
    public static class EdrConfig
    {
        public const string EDRName = "MalwareDetector";
        public const string InstallPath = "C:\\ProgramData\\AntivirusProtection";
        public const string LogPath = "C:\\ProgramData\\AntivirusProtection\\Logs";
        public const string QuarantinePath = "C:\\ProgramData\\AntivirusProtection\\Quarantine";
        public const string ReportsPath = "C:\\ProgramData\\AntivirusProtection\\Reports";
        public const string DataPath = "C:\\ProgramData\\AntivirusProtection\\Data";

        /// <summary>Subfolder under InstallPath for YARA binary and rules (e.g. Yara).</summary>
        public const string YaraSubFolder = "Yara";
        /// <summary>Filename of the YARA executable (expected next to app or under InstallPath\Yara).</summary>
        public const string YaraExeName = "yara.exe";
        /// <summary>Default rules file name (rules.yar).</summary>
        public const string YaraRulesFileName = "rules.yar";

        public const bool AutoKillThreats = true;
        public const bool AutoBlockThreats = false;  // Suspend leaves processes frozen permanently; log only for Medium threat
        public const bool AutoQuarantine = true;
        public const string CirclHashLookupUrl = "https://hashlookup.circl.lu/lookup/sha256";
        public const string CymruApiUrl = "https://api.malwarehash.cymru.com/v1/hash";
        public const string MalwareBazaarApiUrl = "https://mb-api.abuse.ch/api/v1/";
    }
}
