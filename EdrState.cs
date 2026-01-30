using System;

namespace Edr
{
    public static class EdrState
    {
        public static int ThreatCount;
        public static int FilesQuarantined;
        public static int ProcessesTerminated;

        public static int CurrentProcessId { get { return System.Diagnostics.Process.GetCurrentProcess().Id; } }
    }
}
