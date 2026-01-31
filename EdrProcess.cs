using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using System.Threading;

namespace Edr
{
    public static class EdrProcess
    {
        const uint PROCESS_SUSPEND_RESUME = 0x0800;
        const int ProcessCacheSeconds = 90;
        static readonly object _procCacheLock = new object();
        static List<ProcInfo> _procCache;
        static int _procCacheTicks;

        [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr hObject);
        [DllImport("ntdll.dll")] static extern int NtSuspendProcess(IntPtr processHandle);
        public static int CurrentPid { get { return Process.GetCurrentProcess().Id; } }

        public sealed class ProcInfo
        {
            public int ProcessId;
            public string Name;
            public string CommandLine;
            public string ExecutablePath;
            public int ParentProcessId;
        }

        public static List<ProcInfo> GetProcesses(CancellationToken ct)
        {
            int now = Environment.TickCount;
            lock (_procCacheLock)
            {
                if (_procCache != null && (now - _procCacheTicks) < ProcessCacheSeconds * 1000)
                    return _procCache;
            }

            var list = new List<ProcInfo>();
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT ProcessId,Name,CommandLine,ExecutablePath,ParentProcessId FROM Win32_Process"))
                using (var results = searcher.Get())
                {
                    foreach (ManagementBaseObject o in results)
                    {
                        if (ct.IsCancellationRequested) break;
                        var mo = (ManagementObject)o;
                        var p = new ProcInfo
                        {
                            ProcessId = Convert.ToInt32(mo["ProcessId"]),
                            Name = mo["Name"] != null ? mo["Name"].ToString() : "",
                            CommandLine = mo["CommandLine"] != null ? mo["CommandLine"].ToString() : "",
                            ExecutablePath = mo["ExecutablePath"] != null ? mo["ExecutablePath"].ToString() : "",
                            ParentProcessId = mo["ParentProcessId"] != null ? Convert.ToInt32(mo["ParentProcessId"]) : 0
                        };
                        list.Add(p);
                    }
                }
                lock (_procCacheLock)
                {
                    _procCache = list;
                    _procCacheTicks = now;
                }
            }
            catch (Exception ex) { EdrLog.Write("EdrProcess", "GetProcesses error: " + ex.Message, "ERROR"); }
            return list;
        }

        public static ProcInfo GetParent(ProcInfo child, List<ProcInfo> all)
        {
            if (child == null || all == null) return null;
            foreach (var p in all) { if (p.ProcessId == child.ParentProcessId) return p; }
            return null;
        }

        /// <summary>Suspend process to block malware execution (Medium threat). Requires admin.</summary>
        public static void SuspendThreat(int processId, string processName)
        {
            if (processId == CurrentPid) return;
            IntPtr h = IntPtr.Zero;
            try
            {
                h = OpenProcess(PROCESS_SUSPEND_RESUME, false, processId);
                if (h == IntPtr.Zero || h == new IntPtr(-1)) return;
                if (NtSuspendProcess(h) == 0)
                {
                    EdrState.ProcessesSuspended++;
                    EdrLog.Write("EdrProcess", "Suspended threat process: " + processName + " (PID: " + processId + ")", "ACTION");
                }
            }
            catch (Exception ex) { EdrLog.Write("EdrProcess", "Failed to suspend " + processName + ": " + ex.Message, "ERROR"); }
            finally { if (h != IntPtr.Zero && h != new IntPtr(-1)) CloseHandle(h); }
        }

        public static void KillThreat(int processId, string processName)
        {
            if (processId == CurrentPid) return;
            try
            {
                using (var proc = Process.GetProcessById(processId))
                {
                    proc.Kill();
                    EdrState.ProcessesTerminated++;
                    EdrLog.Write("EdrProcess", "Terminated threat process: " + processName + " (PID: " + processId + ")", "ACTION");
                }
            }
            catch (Exception ex) { EdrLog.Write("EdrProcess", "Failed to terminate " + processName + ": " + ex.Message, "ERROR"); }
        }

        public static string GetExecutablePath(int processId)
        {
            try
            {
                using (var s = new ManagementObjectSearcher("SELECT ExecutablePath FROM Win32_Process WHERE ProcessId = " + processId))
                using (var r = s.Get())
                {
                    foreach (ManagementBaseObject o in r)
                    {
                        var path = (o["ExecutablePath"] ?? "").ToString();
                        if (!string.IsNullOrEmpty(path)) return path;
                        return null;
                    }
                }
            }
            catch { }
            return null;
        }

        public static bool GetOwner(int processId, out string domain, out string user)
        {
            domain = null; user = null;
            try
            {
                string q = "SELECT * FROM Win32_Process WHERE ProcessId = " + processId;
                using (var searcher = new ManagementObjectSearcher(q))
                using (var results = searcher.Get())
                {
                    foreach (ManagementBaseObject o in results)
                    {
                        var mo = (ManagementObject)o;
                        string[] argList = new string[] { "", "" };
                        int ret = Convert.ToInt32(mo.InvokeMethod("GetOwner", argList));
                        if (ret == 0) { user = argList[0]; domain = argList[1]; return true; }
                        return false;
                    }
                }
            }
            catch { }
            return false;
        }
    }
}
