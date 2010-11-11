using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Data;
using System.Reflection;
using System.IO;
using System.Text;
using System.Windows.Forms;

namespace CasabaSecurity.Web.Watcher.TeamFoundation
{
    public partial class TeamFoundationPluginConfigPanel : UserControl
    {
        WatcherOutputPlugin plugin;

        public string servername;
        public string projectname;
        public bool sdlfields;
        public bool requiredfields;

        public TeamFoundationPluginConfigPanel()
        {
            InitializeComponent();
        }

        public TeamFoundationPluginConfigPanel(WatcherOutputPlugin outplugin)
        {
            plugin = outplugin;
            InitializeComponent();
        }

        public void Init()
        {
            this.servernametextBox.Text = WatcherEngine.Configuration.GetConfigItem(plugin, "ServerName", "127.0.0.1");
            this.projectnametextBox.Text = WatcherEngine.Configuration.GetConfigItem(plugin, "ProjectName", "Default");
        }

        private void servernametextBox_TextChanged(object sender, EventArgs e)
        {
            servername = servernametextBox.Text;
            WatcherEngine.Configuration.SetConfigItem(plugin, "ServerName", servernametextBox.Text);
        }

        private void projectnametextBox_TextChanged(object sender, EventArgs e)
        {
            projectname = projectnametextBox.Text;
            WatcherEngine.Configuration.SetConfigItem(plugin, "ProjectName", projectnametextBox.Text);
        }

        private void editbutton_Click(object sender, EventArgs e)
        {
            String filename = String.Format(@"{0}\{1}", Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), Resources.AdapterConfigurationFile);

            Process notepad = new Process();
            notepad.StartInfo.FileName = "notepad.exe";
            notepad.StartInfo.Arguments = filename;
            notepad.Start();
        }
    }
}
