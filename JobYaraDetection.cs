using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Threading;

namespace Edr
{
    public sealed class JobYaraDetection : IEdrJob
    {
        public string Name { get { return "YaraDetection"; } }
        public int IntervalSeconds { get { return 90; } }

        const int MaxFilesPerRun = 200;
        const int BatchSize = 40;
        static readonly string[] VcDlls = { "vcruntime140.dll", "msvcp140.dll" };

        static void EnsureVcRuntimeExtracted(string yaraExePath)
        {
            string targetDir = Path.GetDirectoryName(yaraExePath);
            if (string.IsNullOrEmpty(targetDir)) return;
            var asm = Assembly.GetExecutingAssembly();
            if (asm == null) return;
            string[] names = asm.GetManifestResourceNames();
            if (names == null) return;
            foreach (string dllName in VcDlls)
            {
                string destPath = Path.Combine(targetDir, dllName);
                if (File.Exists(destPath)) continue;
                string resName = null;
                string suffix = dllName.Replace(".dll", "");
                foreach (string n in names)
                {
                    if (n.EndsWith("." + suffix, StringComparison.OrdinalIgnoreCase) || n.EndsWith("." + dllName, StringComparison.OrdinalIgnoreCase))
                    { resName = n; break; }
                }
                if (resName == null) continue;
                try
                {
                    using (var stream = asm.GetManifestResourceStream(resName))
                    {
                        if (stream == null) continue;
                        using (var fs = File.Create(destPath))
                            stream.CopyTo(fs);
                    }
                }
                catch { }
            }
        }

        static string GetYaraExePath()
        {
            try
            {
                string exeDir = Path.GetDirectoryName(Process.GetCurrentProcess().MainModule != null ? Process.GetCurrentProcess().MainModule.FileName : null);
                if (!string.IsNullOrEmpty(exeDir))
                {
                    string nextToExe = Path.Combine(exeDir, EdrConfig.YaraExeName);
                    if (File.Exists(nextToExe)) return nextToExe;
                    string inYara = Path.Combine(EdrConfig.InstallPath, EdrConfig.YaraSubFolder, EdrConfig.YaraExeName);
                    if (File.Exists(inYara)) return inYara;
                }
            }
            catch { }
            return null;
        }

        static string GetRulesPath()
        {
            try
            {
                string exeDir = Path.GetDirectoryName(Process.GetCurrentProcess().MainModule != null ? Process.GetCurrentProcess().MainModule.FileName : null);
                if (!string.IsNullOrEmpty(exeDir))
                {
                    string nextToExe = Path.Combine(exeDir, EdrConfig.YaraRulesFileName);
                    if (File.Exists(nextToExe)) return nextToExe;
                }
                string inData = Path.Combine(EdrConfig.DataPath, EdrConfig.YaraRulesFileName);
                if (File.Exists(inData)) return inData;
            }
            catch { }
            return null;
        }

        public void Run(CancellationToken ct)
        {
            string yaraExe = GetYaraExePath();
            string rulesPath = GetRulesPath();
            if (string.IsNullOrEmpty(yaraExe) || string.IsNullOrEmpty(rulesPath))
            {
                EdrLog.Write(Name, "YARA skipped: yara.exe or rules.yar not found (paths: exe next to app, " + EdrConfig.InstallPath + "\\" + EdrConfig.YaraSubFolder + ", " + EdrConfig.DataPath + ").", "INFO", "yara_detections.log");
                return;
            }
            EnsureVcRuntimeExtracted(yaraExe);

            var files = new List<string>();
            foreach (string path in EdrFile.EnumerateSuspiciousFiles(ct))
            {
                if (ct.IsCancellationRequested || files.Count >= MaxFilesPerRun) break;
                if (EdrWhitelist.IsWhitelistedPath(path)) continue;
                try
                {
                    if (File.Exists(path) && new FileInfo(path).Length > 0 && new FileInfo(path).Length < 50 * 1024 * 1024)
                        files.Add(path);
                }
                catch { }
            }

            if (files.Count == 0)
            {
                EdrLog.Write(Name, "YARA scan: no files in scope.", "INFO", "yara_detections.log");
                return;
            }

            int matches = 0;
            for (int i = 0; i < files.Count && !ct.IsCancellationRequested; i += BatchSize)
            {
                int take = Math.Min(BatchSize, files.Count - i);
                var batch = new List<string>();
                for (int j = 0; j < take; j++) batch.Add(files[i + j]);
                int batchMatches = RunYaraBatch(yaraExe, rulesPath, batch, ct);
                matches += batchMatches;
            }

            if (matches > 0)
                EdrLog.Write(Name, "YARA scan completed. Files in scope: " + files.Count + ", matches: " + matches + ".", "THREAT", "yara_detections.log");
            else
                EdrLog.Write(Name, "YARA scan completed. Files in scope: " + files.Count + ", matches: 0.", "INFO", "yara_detections.log");
        }

        static int RunYaraBatch(string yaraExe, string rulesPath, List<string> paths, CancellationToken ct)
        {
            int matches = 0;
            var args = new List<string> { "\"" + rulesPath.Replace("\"", "\"\"") + "\"" };
            foreach (string p in paths)
            {
                try
                {
                    if (File.Exists(p)) args.Add("\"" + p.Replace("\"", "\"\"") + "\"");
                }
                catch { }
            }
            if (args.Count <= 1) return 0;

            string arguments = string.Join(" ", args.ToArray());
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = yaraExe,
                    Arguments = arguments,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                    WorkingDirectory = Path.GetDirectoryName(yaraExe) ?? ""
                };
                using (var proc = Process.Start(psi))
                {
                    if (proc == null) return 0;
                    string stdout = proc.StandardOutput.ReadToEnd();
                    proc.StandardError.ReadToEnd();
                    proc.WaitForExit(60000);
                    foreach (string line in (stdout ?? "").Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                    {
                        if (ct.IsCancellationRequested) break;
                        string trimmed = line.Trim();
                        if (string.IsNullOrEmpty(trimmed)) continue;
                        int firstSpace = trimmed.IndexOf(' ');
                        if (firstSpace <= 0) continue;
                        string ruleName = trimmed.Substring(0, firstSpace);
                        string filePath = trimmed.Substring(firstSpace + 1).Trim();
                        if (string.IsNullOrEmpty(ruleName) || string.IsNullOrEmpty(filePath)) continue;
                        EdrLog.Write("YaraDetection", "YARA match: rule=\"" + ruleName + "\" file=\"" + filePath + "\"", "THREAT", "yara_detections.log");
                        matches++;
                        if (EdrGlobalRules.QuarantineIfAllowed(filePath, "YARA:" + ruleName, ct))
                            EdrState.ThreatCount++;
                    }
                }
            }
            catch (Exception ex)
            {
                EdrLog.Write("YaraDetection", "YARA run error: " + ex.Message, "ERROR", "yara_detections.log");
            }
            return matches;
        }
    }
}
