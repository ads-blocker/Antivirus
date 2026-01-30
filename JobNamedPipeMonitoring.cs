using System;
using System.Threading;

namespace Edr
{
    public sealed class JobNamedPipeMonitoring : IEdrJob
    {
        public string Name { get { return "NamedPipeMonitoring"; } }
        public int IntervalSeconds { get { return 45; } }

        public void Run(CancellationToken ct)
        {
            EdrLog.Write(Name, "Named pipe monitoring tick", "INFO", "named_pipe.log");
        }
    }
}
