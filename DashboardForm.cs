// EDR Dashboard — C# 5.1, WinForms. Modern 2026 layout.

using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Windows.Forms;
using Edr;

class DashboardForm : Form
{
    ListView _recentListView;
    Button _btnPersistence;
    Label _lblInstallStatus;
    Label _lblThreats;
    Label _lblHeaderStatus;
    Panel _header;

    // Modern 2026 palette — refined dark
    static readonly Color BgMain = Color.FromArgb(15, 23, 42);
    static readonly Color BgCard = Color.FromArgb(30, 41, 59);
    static readonly Color BgSidebar = Color.FromArgb(24, 33, 51);
    static readonly Color Border = Color.FromArgb(51, 65, 85);
    static readonly Color TextPrimary = Color.FromArgb(248, 250, 252);
    static readonly Color TextMuted = Color.FromArgb(148, 163, 184);
    static readonly Color Accent = Color.FromArgb(34, 211, 238);
    static readonly Color Success = Color.FromArgb(74, 222, 128);
    static readonly Color Danger = Color.FromArgb(248, 113, 113);

    public DashboardForm(Icon appIcon)
    {
        Text = EdrConfig.EDRName + " — Dashboard";
        Size = new Size(1000, 680);
        MinimumSize = new Size(880, 520);
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.Sizable;
        MinimizeBox = true;
        MaximizeBox = true;
        BackColor = BgMain;
        ForeColor = TextPrimary;
        Font = new Font("Segoe UI", 9.5F);
        if (appIcon != null) Icon = appIcon;

        _header = new Panel
        {
            Dock = DockStyle.Top,
            Height = 64,
            BackColor = BgSidebar,
            Padding = new Padding(24, 0, 24, 0)
        };
        var lblTitle = new Label
        {
            Text = EdrConfig.EDRName,
            Font = new Font("Segoe UI", 18F, FontStyle.Bold),
            ForeColor = TextPrimary,
            AutoSize = true,
            Location = new Point(24, 8)
        };
        _lblHeaderStatus = new Label
        {
            Text = "Protection active",
            ForeColor = Success,
            AutoSize = true,
            Font = new Font("Segoe UI", 10F)
        };
        _lblThreats = new Label
        {
            Text = "Threats: " + EdrState.ThreatCount,
            ForeColor = TextMuted,
            AutoSize = true,
            Font = new Font("Segoe UI", 9.5F)
        };
        _header.Controls.Add(lblTitle);
        _header.Controls.Add(_lblHeaderStatus);
        _header.Controls.Add(_lblThreats);
        _header.Resize += (s, e) => LayoutHeader();

        var sidebar = new Panel
        {
            Dock = DockStyle.Left,
            Width = 200,
            BackColor = BgSidebar,
            Padding = new Padding(0)
        };
        int y = 20;
        var lblNav = new Label { Text = "Actions", ForeColor = TextMuted, Font = new Font("Segoe UI", 8.5F), AutoSize = true, Location = new Point(16, y) };
        sidebar.Controls.Add(lblNav);
        y += 22;
        AddNavButton(sidebar, "Quick scan", ref y, () => OnQuickScan());
        AddNavButton(sidebar, "Full scan", ref y, () => OnFullScan());
        AddNavButton(sidebar, "Quarantine", ref y, () => OnQuarantine());
        AddNavButton(sidebar, "Logs", ref y, () => OnLogs());
        AddNavButton(sidebar, "Alerts", ref y, () => OnAlerts());
        AddNavButton(sidebar, "Settings", ref y, () => OnSettings());
        y += 24;
        var lblInst = new Label { Text = "Install & persistence", ForeColor = TextMuted, Font = new Font("Segoe UI", 8.5F), AutoSize = true, Location = new Point(16, y) };
        sidebar.Controls.Add(lblInst);
        y += 22;
        AddNavButton(sidebar, "Install", ref y, () => OnInstall());
        _btnPersistence = AddNavButton(sidebar, "Enable persistence", ref y, () => OnPersistence());
        AddNavButton(sidebar, "Uninstall", ref y, () => OnUninstall());
        _lblInstallStatus = new Label
        {
            Text = "",
            ForeColor = TextMuted,
            Font = new Font("Segoe UI", 8F),
            AutoSize = true,
            Location = new Point(16, y + 8),
            MaximumSize = new Size(168, 0)
        };
        sidebar.Controls.Add(_lblInstallStatus);

        var main = new Panel { Dock = DockStyle.Fill, BackColor = BgMain, Padding = new Padding(24) };

        var cardActions = CreateCard();
        cardActions.Size = new Size(main.ClientSize.Width - 48, 92);
        cardActions.Location = new Point(0, 0);
        cardActions.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
        var lblActions = new Label
        {
            Text = "Quick actions",
            ForeColor = TextPrimary,
            Font = new Font("Segoe UI", 11F, FontStyle.Bold),
            AutoSize = true,
            Location = new Point(20, 18)
        };
        var btnQuickMain = new Button
        {
            Text = "Quick scan",
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.FromArgb(51, 65, 85),
            ForeColor = Accent,
            Size = new Size(124, 36),
            Location = new Point(20, 44),
            Font = new Font("Segoe UI", 9.5F),
            Cursor = Cursors.Hand
        };
        btnQuickMain.FlatAppearance.BorderColor = Border;
        btnQuickMain.FlatAppearance.MouseOverBackColor = Color.FromArgb(71, 85, 105);
        btnQuickMain.Click += (s, e) => OnQuickScan();
        var btnFullMain = new Button
        {
            Text = "Full scan",
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.FromArgb(51, 65, 85),
            ForeColor = Accent,
            Size = new Size(124, 36),
            Location = new Point(156, 44),
            Font = new Font("Segoe UI", 9.5F),
            Cursor = Cursors.Hand
        };
        btnFullMain.FlatAppearance.BorderColor = Border;
        btnFullMain.FlatAppearance.MouseOverBackColor = Color.FromArgb(71, 85, 105);
        btnFullMain.Click += (s, e) => OnFullScan();
        cardActions.Controls.Add(lblActions);
        cardActions.Controls.Add(btnQuickMain);
        cardActions.Controls.Add(btnFullMain);

        var cardModules = CreateCard();
        cardModules.Location = new Point(0, 108);
        cardModules.Size = new Size(main.ClientSize.Width - 48, 196);
        cardModules.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
        var lblMod = new Label
        {
            Text = "Detection modules",
            ForeColor = TextPrimary,
            Font = new Font("Segoe UI", 11F, FontStyle.Bold),
            AutoSize = true,
            Location = new Point(20, 18)
        };
        cardModules.Controls.Add(lblMod);
        var flp = new FlowLayoutPanel
        {
            Location = new Point(20, 50),
            Size = new Size(cardModules.Width - 40, 132),
            Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = true,
            AutoScroll = true,
            BackColor = Color.Transparent,
            Padding = new Padding(0)
        };
        var modules = new[]
        {
            "Hash", "LOLBin", "Process anomaly", "AMSI bypass", "Credential dump", "Credential protection", "WMI persistence",
            "Scheduled tasks", "Registry persistence", "DLL hijacking", "Token manipulation",
            "Process hollowing", "Keylogger", "Ransomware", "Network anomaly", "Rootkit",
            "Clipboard", "Browser extensions", "Shadow copy", "USB", "Attack tools",
            "Advanced threat", "Event log", "Firewall", "Services", "Fileless", "Memory",
            "Named pipes", "DNS exfil", "Webcam", "Beacon", "Code injection", "Data exfil",
            "Lateral movement", "Process creation", "Quarantine mgmt", "Simple AV",
            "Response engine", "GFocus", "MITRE", "IDS", "YARA"
        };
        foreach (var m in modules)
        {
            var chk = new CheckBox
            {
                Text = m,
                ForeColor = TextMuted,
                AutoSize = true,
                Checked = true,
                Margin = new Padding(0, 6, 24, 6),
                Font = new Font("Segoe UI", 9F)
            };
            flp.Controls.Add(chk);
        }
        cardModules.Controls.Add(flp);

        var cardActivity = CreateCard();
        cardActivity.Location = new Point(0, 316);
        cardActivity.Size = new Size(main.ClientSize.Width - 48, Math.Max(200, main.ClientSize.Height - 356));
        cardActivity.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
        var lblAct = new Label
        {
            Text = "Recent activity",
            ForeColor = TextPrimary,
            Font = new Font("Segoe UI", 11F, FontStyle.Bold),
            AutoSize = true,
            Location = new Point(20, 18)
        };
        cardActivity.Controls.Add(lblAct);
        var lv = new ListView
        {
            View = View.Details,
            FullRowSelect = true,
            GridLines = false,
            BackColor = Color.FromArgb(30, 41, 59),
            ForeColor = TextPrimary,
            BorderStyle = BorderStyle.None,
            Location = new Point(20, 50),
            Size = new Size(cardActivity.Width - 40, Math.Max(120, cardActivity.Height - 70)),
            Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right,
            Font = new Font("Segoe UI", 9F)
        };
        lv.Columns.Add("Time", 160);
        lv.Columns.Add("Type", 90);
        lv.Columns.Add("Details", 400);
        lv.Items.Add(new ListViewItem(new[] { DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), "Info", "Dashboard opened." }));
        _recentListView = lv;
        cardActivity.Controls.Add(lv);

        main.Controls.Add(cardActions);
        main.Controls.Add(cardModules);
        main.Controls.Add(cardActivity);

        main.Resize += (s, e) =>
        {
            int w = main.ClientSize.Width - 48;
            cardActions.Width = w;
            cardModules.Width = w;
            cardActivity.Width = w;
            cardActivity.Height = Math.Max(200, main.ClientSize.Height - 356);
            flp.Width = cardModules.Width - 40;
            lv.Width = cardActivity.Width - 40;
            lv.Height = Math.Max(120, cardActivity.Height - 70);
            SizeListViewColumns(lv);
        };

        Controls.Add(main);
        Controls.Add(sidebar);
        Controls.Add(_header);

        Load += (s, e) =>
        {
            RefreshInstallStatus();
            RefreshThreats();
            LayoutHeader();
            int w = Math.Max(400, main.ClientSize.Width - 48);
            cardActions.Width = w;
            cardModules.Width = w;
            cardActivity.Width = w;
            cardActivity.Height = Math.Max(200, main.ClientSize.Height - 356);
            flp.Width = cardModules.Width - 40;
            lv.Width = cardActivity.Width - 40;
            lv.Height = Math.Max(120, cardActivity.Height - 70);
            SizeListViewColumns(lv);
        };
    }

    void LayoutHeader()
    {
        if (_header == null || _lblThreats == null || _lblHeaderStatus == null) return;
        try
        {
            var r = _header.ClientRectangle;
            int right = r.Right - 24;
            int y = 22;
            _lblThreats.Location = new Point(right - _lblThreats.PreferredWidth, y);
            _lblHeaderStatus.Location = new Point(_lblThreats.Left - _lblHeaderStatus.PreferredWidth - 20, y);
        }
        catch { }
    }

    void SizeListViewColumns(ListView lv)
    {
        if (lv == null || lv.Columns.Count < 3) return;
        try
        {
            int w = Math.Max(200, lv.ClientSize.Width - 4);
            lv.Columns[0].Width = 160;
            lv.Columns[1].Width = 90;
            lv.Columns[2].Width = Math.Max(100, w - 250);
        }
        catch { }
    }

    Panel CreateCard()
    {
        var p = new Panel { BackColor = BgCard };
        p.Paint += (s, e) =>
        {
            using (var pen = new Pen(Border, 1f))
                e.Graphics.DrawRectangle(pen, 0, 0, p.Width - 1, p.Height - 1);
        };
        return p;
    }

    Button AddNavButton(Panel p, string text, ref int y, Action click)
    {
        var btn = new Button
        {
            Text = "  " + text,
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.Transparent,
            ForeColor = TextPrimary,
            Size = new Size(168, 36),
            Location = new Point(16, y),
            TextAlign = ContentAlignment.MiddleLeft,
            Font = new Font("Segoe UI", 9.5F),
            Cursor = Cursors.Hand
        };
        btn.FlatAppearance.BorderSize = 0;
        btn.FlatAppearance.MouseOverBackColor = Color.FromArgb(51, 65, 85);
        btn.Click += (s, e) => click();
        y += 40;
        p.Controls.Add(btn);
        return btn;
    }

    void RefreshThreats() { if (_lblThreats != null) _lblThreats.Text = "Threats: " + EdrState.ThreatCount; }
    void RefreshInstallStatus()
    {
        bool inst = EdrInstall.IsInstalled();
        bool pers = EdrInstall.IsPersisted();
        if (_lblInstallStatus != null) _lblInstallStatus.Text = "Installed: " + (inst ? "Yes" : "No") + "  |  Persistence: " + (pers ? "On" : "Off");
        if (_btnPersistence != null) _btnPersistence.Text = pers ? "  Disable persistence" : "  Enable persistence";
    }

    void AddRecent(string type, string details)
    {
        if (_recentListView != null)
            _recentListView.Items.Insert(0, new ListViewItem(new[] { DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), type, details }));
        RefreshThreats();
    }

    void OnQuickScan()
    {
        try
        {
            if (!Directory.Exists(EdrConfig.LogPath)) Directory.CreateDirectory(EdrConfig.LogPath);
            EdrLog.Write(EdrConfig.EDRName, "Quick scan requested from dashboard.", "INFO", "dashboard.log");
            AddRecent("Info", "Quick scan requested. Scans run periodically (ResponseEngine, YARA).");
            Process.Start("explorer.exe", "\"" + EdrConfig.LogPath + "\"");
        }
        catch (Exception ex) { MessageBox.Show(this, "Quick scan: " + ex.Message, EdrConfig.EDRName, MessageBoxButtons.OK, MessageBoxIcon.Warning); }
    }

    void OnFullScan()
    {
        try
        {
            if (!Directory.Exists(EdrConfig.LogPath)) Directory.CreateDirectory(EdrConfig.LogPath);
            EdrLog.Write(EdrConfig.EDRName, "Full scan requested from dashboard.", "INFO", "dashboard.log");
            AddRecent("Info", "Full scan requested. YARA and ResponseEngine jobs cover suspicious paths.");
            Process.Start("explorer.exe", "\"" + EdrConfig.LogPath + "\"");
        }
        catch (Exception ex) { MessageBox.Show(this, "Full scan: " + ex.Message, EdrConfig.EDRName, MessageBoxButtons.OK, MessageBoxIcon.Warning); }
    }

    void OnQuarantine()
    {
        try
        {
            if (!Directory.Exists(EdrConfig.QuarantinePath)) Directory.CreateDirectory(EdrConfig.QuarantinePath);
            Process.Start("explorer.exe", "\"" + EdrConfig.QuarantinePath + "\"");
            AddRecent("Info", "Opened quarantine folder.");
        }
        catch (Exception ex) { MessageBox.Show(this, "Quarantine: " + ex.Message, EdrConfig.EDRName, MessageBoxButtons.OK, MessageBoxIcon.Warning); }
    }

    void OnLogs()
    {
        try
        {
            if (!Directory.Exists(EdrConfig.LogPath)) Directory.CreateDirectory(EdrConfig.LogPath);
            Process.Start("explorer.exe", "\"" + EdrConfig.LogPath + "\"");
            AddRecent("Info", "Opened logs folder.");
        }
        catch (Exception ex) { MessageBox.Show(this, "Logs: " + ex.Message, EdrConfig.EDRName, MessageBoxButtons.OK, MessageBoxIcon.Warning); }
    }

    void OnAlerts()
    {
        try
        {
            if (!Directory.Exists(EdrConfig.LogPath)) Directory.CreateDirectory(EdrConfig.LogPath);
            string alertPath = Path.Combine(EdrConfig.LogPath, "yara_detections.log");
            if (!File.Exists(alertPath)) alertPath = Path.Combine(EdrConfig.LogPath, "response_engine.log");
            if (File.Exists(alertPath))
            {
                string[] lines = File.ReadAllLines(alertPath);
                int take = Math.Min(20, lines.Length);
                string preview = take == 0 ? "(empty)" : string.Join(Environment.NewLine, lines, Math.Max(0, lines.Length - take), take);
                MessageBox.Show(this, "Last " + take + " line(s) from " + Path.GetFileName(alertPath) + ":\n\n" + preview, EdrConfig.EDRName + " — Alerts", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
                Process.Start("explorer.exe", "\"" + EdrConfig.LogPath + "\"");
            AddRecent("Info", "Viewed alerts.");
        }
        catch (Exception ex) { MessageBox.Show(this, "Alerts: " + ex.Message, EdrConfig.EDRName, MessageBoxButtons.OK, MessageBoxIcon.Warning); }
    }

    void OnSettings()
    {
        string msg = "Paths:" + Environment.NewLine
            + "  Install: " + EdrConfig.InstallPath + Environment.NewLine
            + "  Logs: " + EdrConfig.LogPath + Environment.NewLine
            + "  Quarantine: " + EdrConfig.QuarantinePath + Environment.NewLine
            + "  Data: " + EdrConfig.DataPath + Environment.NewLine
            + "Options: AutoQuarantine=" + EdrConfig.AutoQuarantine + ", AutoKillThreats=" + EdrConfig.AutoKillThreats;
        MessageBox.Show(this, msg, EdrConfig.EDRName + " — Settings", MessageBoxButtons.OK, MessageBoxIcon.Information);
        try { if (!Directory.Exists(EdrConfig.DataPath)) Directory.CreateDirectory(EdrConfig.DataPath); Process.Start("explorer.exe", "\"" + EdrConfig.DataPath + "\""); } catch { }
        AddRecent("Info", "Viewed settings.");
    }

    void OnInstall()
    {
        try
        {
            string err = EdrInstall.Install();
            if (err != null) { MessageBox.Show(this, err, EdrConfig.EDRName, MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
            RefreshInstallStatus();
            AddRecent("Info", "Installed to " + EdrConfig.InstallPath);
            MessageBox.Show(this, "Installed to " + EdrConfig.InstallPath + ". Use Enable persistence to start with Windows.", EdrConfig.EDRName, MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (Exception ex) { MessageBox.Show(this, "Install: " + ex.Message, EdrConfig.EDRName, MessageBoxButtons.OK, MessageBoxIcon.Warning); }
    }

    void OnPersistence()
    {
        try
        {
            bool pers = EdrInstall.IsPersisted();
            string err = pers ? EdrInstall.DisablePersistence() : EdrInstall.EnablePersistence();
            if (err != null) { MessageBox.Show(this, err, EdrConfig.EDRName, MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
            RefreshInstallStatus();
            AddRecent("Info", pers ? "Persistence disabled." : "Persistence enabled.");
        }
        catch (Exception ex) { MessageBox.Show(this, "Persistence: " + ex.Message, EdrConfig.EDRName, MessageBoxButtons.OK, MessageBoxIcon.Warning); }
    }

    void OnUninstall()
    {
        var res = MessageBox.Show(this, "Remove persistence and delete " + EdrConfig.InstallPath + "?\n\nIf the app is running from that folder, deletion may fail until you close it.", EdrConfig.EDRName + " — Uninstall", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
        if (res != DialogResult.Yes) return;
        try
        {
            string err = EdrInstall.Uninstall();
            if (err != null) { MessageBox.Show(this, err, EdrConfig.EDRName, MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
            RefreshInstallStatus();
            AddRecent("Info", "Uninstalled; install folder removed.");
            MessageBox.Show(this, "Uninstall complete. Persistence removed and install folder deleted.", EdrConfig.EDRName, MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (Exception ex) { MessageBox.Show(this, "Uninstall: " + ex.Message, EdrConfig.EDRName, MessageBoxButtons.OK, MessageBoxIcon.Warning); }
    }
}
