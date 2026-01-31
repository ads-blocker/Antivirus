using System;
using System.Threading;
using System.Windows.Forms;

namespace Edr
{
    public sealed class JobClipboardMonitoring : IEdrJob
    {
        public string Name { get { return "ClipboardMonitoring"; } }
        public int IntervalSeconds { get { return 90; } }

        public void Run(CancellationToken ct)
        {
            try
            {
                if (Thread.CurrentThread.GetApartmentState() != ApartmentState.STA) return;
                if (Clipboard.ContainsText())
                {
                    string t = Clipboard.GetText();
                    if (t != null && t.Length > 500)
                        EdrLog.Write(Name, "Large clipboard text length: " + t.Length, "INFO", "clipboard_monitoring.log");
                }
            }
            catch (Exception ex) { EdrLog.Write(Name, "Error: " + ex.Message, "ERROR", "clipboard_monitoring.log"); }
        }
    }
}
