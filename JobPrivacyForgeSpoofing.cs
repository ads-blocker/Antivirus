using System;
using System.Threading;

namespace Edr
{
    public sealed class JobPrivacyForgeSpoofing : IEdrJob
    {
        public string Name { get { return "PrivacyForgeSpoofing"; } }
        public int IntervalSeconds { get { return 60; } }

        public void Run(CancellationToken ct)
        {
            EdrLog.Write(Name, "PrivacyForge spoofing tick", "INFO", "privacy_forge.log");
        }
    }
}
