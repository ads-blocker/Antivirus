using System;
using System.IO;

namespace Edr
{
    public static class EdrLog
    {
        static readonly object _lock = new object();

        public static void Write(string source, string message, string level = "INFO")
        {
            WriteToFile(source, message, level, null);
        }

        public static void Write(string source, string message, string level, string logFile)
        {
            WriteToFile(source, message, level, logFile);
        }

        static void WriteToFile(string source, string message, string level, string logFile)
        {
            string line = string.Format("[{0:yyyy-MM-dd HH:mm:ss}] [{1}] [{2}] {3}",
                DateTime.Now, level, source, message);
            lock (_lock)
            {
                try
                {
                    if (!Directory.Exists(EdrConfig.LogPath))
                        Directory.CreateDirectory(EdrConfig.LogPath);
                    string fileName = string.IsNullOrEmpty(logFile) ? "edr_" + DateTime.Now.ToString("yyyy-MM-dd") + ".log" : logFile;
                    string path = Path.Combine(EdrConfig.LogPath, fileName);
                    File.AppendAllText(path, line + Environment.NewLine);
                }
                catch { }
            }
        }
    }
}
