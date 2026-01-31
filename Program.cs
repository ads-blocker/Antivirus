// EDR tray app — C# 5.1, no PowerShell.
// Build: Build.ps1 (csc + app.manifest + Autorun.ico)

using System;
using System.Drawing;
using System.IO;
using System.Windows.Forms;
using Edr;

static class Program
{
    static NotifyIcon TrayIcon;
    static ContextMenuStrip TrayMenu;
    static Form DashboardForm;
    static JobRunner Runner;
    static System.Threading.Timer StartDelayTimer;
    const int StartupDelaySeconds = 90;

    [STAThread]
    static void Main()
    {
        try
        {
            EdrEmbedded.ExtractEmbeddedFiles();
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            Runner = new JobRunner();
            JobRegistration.RegisterAll(Runner);
            StartDelayTimer = new System.Threading.Timer(_ =>
            {
                try { Runner.Start(); } catch { }
            }, null, StartupDelaySeconds * 1000, System.Threading.Timeout.Infinite);

            Icon ico = LoadTrayIcon();
            TrayMenu = new ContextMenuStrip();
            var dashboard = new ToolStripMenuItem("Dashboard");
            dashboard.Click += (s, e) => ShowDashboard();
            var exit = new ToolStripMenuItem("Exit");
            exit.Click += (s, e) => ExitApp();
            TrayMenu.Items.Add(dashboard);
            TrayMenu.Items.Add(new ToolStripSeparator());
            TrayMenu.Items.Add(exit);

            TrayIcon = new NotifyIcon();
            TrayIcon.Icon = ico;
            TrayIcon.Text = "Antivirus Protection";
            TrayIcon.ContextMenuStrip = TrayMenu;
            TrayIcon.Visible = true;
            TrayIcon.DoubleClick += (s, e) => ShowDashboard();

            Application.Run();
        }
        catch (Exception ex)
        {
            try { MessageBox.Show("Startup failed: " + ex.Message, "Antivirus Protection", MessageBoxButtons.OK, MessageBoxIcon.Error); } catch { }
        }
        finally
        {
            if (StartDelayTimer != null) { try { StartDelayTimer.Dispose(); } catch { } StartDelayTimer = null; }
            if (TrayIcon != null) { TrayIcon.Visible = false; TrayIcon.Dispose(); TrayIcon = null; }
            if (Runner != null) { try { Runner.Stop(); } catch { } Runner = null; }
        }
    }

    static Icon LoadTrayIcon()
    {
        try
        {
            var asm = System.Reflection.Assembly.GetExecutingAssembly();
            using (var stream = asm.GetManifestResourceStream("Autorun.ico"))
            {
                if (stream != null)
                    return new Icon(stream);
            }
        }
        catch { }
        
        string baseDir = AppDomain.CurrentDomain.BaseDirectory;
        string path = Path.Combine(baseDir, "Autorun.ico");
        if (File.Exists(path))
        {
            try { return new Icon(path); }
            catch { }
        }
        
        return SystemIcons.Shield;
    }

    static void ShowDashboard()
    {
        if (DashboardForm != null)
        {
            DashboardForm.Show();
            DashboardForm.BringToFront();
            return;
        }
        DashboardForm = new DashboardForm(LoadTrayIcon());
        DashboardForm.FormClosed += (s, e) => { DashboardForm = null; };
        DashboardForm.Show();
    }

    static void ExitApp()
    {
        if (Runner != null) { Runner.Stop(); Runner = null; }
        if (TrayIcon != null) { TrayIcon.Visible = false; TrayIcon.Dispose(); TrayIcon = null; }
        if (DashboardForm != null) { DashboardForm.Close(); DashboardForm = null; }
        Application.Exit();
    }
}
