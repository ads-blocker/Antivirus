using System;
using System.Threading;

namespace Edr
{
    public sealed class JobKeyScramblerManagement : IEdrJob
    {
        public string Name { get { return "KeyScramblerManagement"; } }
        public int IntervalSeconds { get { return 60; } }

        public void Run(CancellationToken ct)
        {
        }
    }
}
