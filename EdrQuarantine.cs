using System;
using System.IO;

namespace Edr
{
    public static class EdrQuarantine
    {
        public static bool MoveToQuarantine(string filePath, string reason)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath)) return false;
            try
            {
                if (!Directory.Exists(EdrConfig.QuarantinePath))
                    Directory.CreateDirectory(EdrConfig.QuarantinePath);
                string fileName = Path.GetFileName(filePath);
                string dest = Path.Combine(EdrConfig.QuarantinePath, DateTime.UtcNow.Ticks + "_" + fileName);
                File.Move(filePath, dest);
                EdrState.FilesQuarantined++;
                EdrLog.Write("EdrQuarantine", "Quarantined: " + filePath + " (Reason: " + reason + ")", "THREAT");
                return true;
            }
            catch (Exception ex)
            {
                EdrLog.Write("EdrQuarantine", "Quarantine failed for " + filePath + ": " + ex.Message, "ERROR");
                return false;
            }
        }
    }
}
