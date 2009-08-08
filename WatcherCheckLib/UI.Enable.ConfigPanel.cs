// WATCHER
//
// UI.Enable.ConfigPanel.cs
// Main implementation of the config panel.
//
// Copyright (c) 2009 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Data;
using System.Text;
using System.Windows.Forms;
using CasabaSecurity.Web.Watcher;

namespace CasabaSecurity.Web.Watcher.Checks
{
    public partial class EnableCheckConfigPanel : UserControl
    {
        WatcherCheck watchercheck;

        public EnableCheckConfigPanel()
        {
            InitializeComponent();
        }

        public EnableCheckConfigPanel(WatcherCheck watcher)
        {
            watchercheck = watcher;
            InitializeComponent();
        }

        public EnableCheckConfigPanel(WatcherCheck watcher, String title, String filterdisc)
        {
            watchercheck = watcher;
            InitializeComponent();
            cookiecheckgroupBox.Text = title;
            enablefiltercheckBox.Text = filterdisc;
        }

        public void Init()
        {
            string configstring = WatcherEngine.Configuration.GetCheckConfig(watchercheck, "Filter", "False");
            if (configstring == "True")
            {
                enablefiltercheckBox.CheckState = CheckState.Checked;
            }
            else
            {
                enablefiltercheckBox.CheckState = CheckState.Unchecked;
            }
        }

        private void enablefiltercheckBox_CheckedChanged(object sender, EventArgs e)
        {
            WatcherEngine.Configuration.SetCheckConfig(watchercheck,"Filter",enablefiltercheckBox.Checked.ToString());
        }
    }
}
