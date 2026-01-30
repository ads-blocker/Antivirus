using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;

namespace Edr
{
    public struct ScheduledTaskInfo
    {
        public string TaskName;
        public string State;
        public string RunAsUser;
        public string Execute;
    }

    public static class EdrScheduledTask
    {
        public static List<ScheduledTaskInfo> QueryTasks()
        {
            var list = new List<ScheduledTaskInfo>();
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "schtasks",
                    Arguments = "/query /fo LIST /v",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };
                using (var p = Process.Start(psi))
                using (var r = p.StandardOutput)
                {
                    string line;
                    var cur = new ScheduledTaskInfo();
                    while ((line = r.ReadLine()) != null)
                    {
                        if (line.StartsWith("TaskName:", StringComparison.OrdinalIgnoreCase))
                            cur.TaskName = line.Substring(9).Trim();
                        else if (line.StartsWith("Status:", StringComparison.OrdinalIgnoreCase))
                            cur.State = line.Substring(7).Trim();
                        else if (line.StartsWith("Run As User:", StringComparison.OrdinalIgnoreCase))
                            cur.RunAsUser = line.Substring(12).Trim();
                        else if (line.StartsWith("Task To Run:", StringComparison.OrdinalIgnoreCase))
                        {
                            cur.Execute = line.Substring(12).Trim();
                            list.Add(cur);
                            cur = new ScheduledTaskInfo();
                        }
                    }
                }
            }
            catch (Exception ex) { EdrLog.Write("EdrScheduledTask", "QueryTasks error: " + ex.Message, "ERROR"); }
            return list;
        }

        public static bool IsSuspicious(ScheduledTaskInfo t)
        {
            if (string.IsNullOrEmpty(t.Execute)) return false;
            string exe = t.Execute.ToLowerInvariant();
            if (exe.IndexOf("powershell", StringComparison.OrdinalIgnoreCase) < 0 &&
                exe.IndexOf("cmd", StringComparison.OrdinalIgnoreCase) < 0 &&
                exe.IndexOf("wscript", StringComparison.OrdinalIgnoreCase) < 0 &&
                exe.IndexOf("cscript", StringComparison.OrdinalIgnoreCase) < 0 &&
                exe.IndexOf("mshta", StringComparison.OrdinalIgnoreCase) < 0)
                return false;
            string user = (t.RunAsUser ?? "").ToLowerInvariant();
            if (user.IndexOf("system") >= 0 || user.IndexOf("administrator") >= 0) return false;
            if ((t.TaskName ?? "").StartsWith("AntivirusAutoRestart_", StringComparison.OrdinalIgnoreCase)) return false;
            if (string.Equals(t.TaskName, "AntivirusProtection", StringComparison.OrdinalIgnoreCase)) return false;
            return true;
        }
    }
}
