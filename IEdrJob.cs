using System.Threading;

namespace Edr
{
    public interface IEdrJob
    {
        string Name { get; }
        int IntervalSeconds { get; }
        void Run(CancellationToken ct);
    }
}
