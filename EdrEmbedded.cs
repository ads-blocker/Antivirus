using System;
using System.IO;
using System.Reflection;

namespace Edr
{
    /// <summary>Extracts embedded files (VC++ DLLs, yara.exe, rules.yar) to exe directory for single-file distribution.</summary>
    public static class EdrEmbedded
    {
        static readonly string[] ExtractNames = { "vcruntime140.dll", "msvcp140.dll", "yara.exe", "rules.yar" };

        public static void ExtractEmbeddedFiles()
        {
            string targetDir = AppDomain.CurrentDomain.BaseDirectory;
            if (string.IsNullOrEmpty(targetDir) || !Directory.Exists(targetDir)) return;
            var asm = Assembly.GetExecutingAssembly();
            if (asm == null) return;
            string[] names = asm.GetManifestResourceNames();
            if (names == null) return;
            foreach (string fileName in ExtractNames)
            {
                string destPath = Path.Combine(targetDir, fileName);
                if (File.Exists(destPath)) continue;
                string resName = FindResourceName(names, fileName);
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

        static string FindResourceName(string[] names, string fileName)
        {
            string suffix = Path.GetFileNameWithoutExtension(fileName);
            string ext = Path.GetExtension(fileName);
            foreach (string n in names)
            {
                if (n.EndsWith("." + suffix, StringComparison.OrdinalIgnoreCase) ||
                    n.EndsWith("." + fileName, StringComparison.OrdinalIgnoreCase))
                    return n;
            }
            return null;
        }
    }
}
