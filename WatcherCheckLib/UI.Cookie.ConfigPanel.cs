// WATCHER
//
// UI.Cookie.ConfigPanel.cs
// Main implementation of UI's Cookie config panel.
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
    public partial class CookieCheckConfigPanel : UserControl
    {
        WatcherCheck watchercheck;

        public CookieCheckConfigPanel()
        {
            InitializeComponent();
        }

        public CookieCheckConfigPanel(WatcherCheck watcher)
        {
            watchercheck = watcher;
            InitializeComponent();
        }

        public CookieCheckConfigPanel(WatcherCheck watcher, String title, String filterdisc)
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
            configstring = WatcherEngine.Configuration.GetCheckConfig(watchercheck, "CookieList");
            if (!String.IsNullOrEmpty(configstring))
            {
                char[] splitter = new char[1];
                splitter[0] = ',';
                string[] errorlist = configstring.Split(splitter);
                this.cookiechecklistBox.BeginUpdate();
                for (int i = 0; i < errorlist.Length; i++)
                {
                    //Items are stored encoded
                    ListViewItem message = new ListViewItem(Watcher.Utility.Base64Decode(errorlist[i]));
                    this.cookiechecklistBox.Items.Add(message);
                    this.cookiechecklistBox.Text = "";
                }
                
            }
            watchercheck.UpdateWordList();
            configstring = WatcherEngine.Configuration.GetCheckConfig(watchercheck, "CookieFilterType", "Inclusive Filter");
            if (configstring == "Inclusive Filter")
            {
                this.filtertypecomboBox.SelectedItem = configstring;
                this.cookiegroupBox.Text = "Cookies to check:";
            }
            else
            {
                this.filtertypecomboBox.SelectedItem = configstring;
                this.cookiegroupBox.Text = "Cookies to ignore:";
            }
        }

        public string GetFilterState()
        {
            lock (this)
            {
                return (string)this.filtertypecomboBox.SelectedItem;
            }
        }

        private void enablefiltercheckBox_CheckedChanged(object sender, EventArgs e)
        {
            lock (this)
            {
                WatcherEngine.Configuration.SetCheckConfig(watchercheck, "Filter", enablefiltercheckBox.Checked.ToString());
            }
        }

        private void addbutton_Click(object sender, EventArgs e)
        {
            string cookienameText = this.cookiecheckentrytextBox.Text.Trim();

            if (cookienameText.Length <= 0)
                return;

            ListViewItem message = new ListViewItem(cookienameText);

            this.cookiechecklistBox.BeginUpdate();
            // skip duplicates
            if (!this.cookiechecklistBox.Items.Contains(message))
            {
                this.cookiechecklistBox.Items.Add(message);
            }
            else
            {
                MessageBox.Show("\"" + cookienameText + "\" is already in the cookie list", "Error");
            }
            this.cookiechecklistBox.EndUpdate();

            List<string> tempstring = new List<string>();
            foreach (ListViewItem item in this.cookiechecklistBox.Items)
            {
                tempstring.Add(Watcher.Utility.Base64Encode(item.Text));
            }
            WatcherEngine.Configuration.SetCheckConfig(watchercheck, "CookieList", (String)String.Join(",", tempstring.ToArray()));

            this.cookiecheckentrytextBox.Text = "";
            watchercheck.UpdateWordList();
        }

        private void deletebutton_Click(object sender, EventArgs e)
        {
            if (this.cookiechecklistBox.SelectedItems.Count < 0)
            {
                MessageBox.Show("You must select a cookie to delete from the cookie list", "Error");
                return;
            }

            this.cookiechecklistBox.BeginUpdate();
            foreach (ListViewItem item in this.cookiechecklistBox.SelectedItems)
            {
                this.cookiechecklistBox.Items.Remove(item);
            }
            this.cookiechecklistBox.EndUpdate();

            List<string> tempstring = new List<string>();
            foreach (ListViewItem item in this.cookiechecklistBox.Items)
            {
                tempstring.Add(Watcher.Utility.Base64Encode(item.Text));
            }
            WatcherEngine.Configuration.SetCheckConfig(watchercheck, "CookieList", String.Join(",", tempstring.ToArray()));
            watchercheck.UpdateWordList();
        }

        private void filtertypecomboBox_SelectedIndexChanged(object sender, EventArgs e)
        {
            string selection = this.filtertypecomboBox.SelectedItem.ToString();
            if (selection == "Inclusive Filter")
            {
                this.cookiegroupBox.Text = "Cookies to check:";
            }
            else
            {
                this.cookiegroupBox.Text = "Cookies to ignore:";
            }
            WatcherEngine.Configuration.SetCheckConfig(watchercheck, "CookieFilterType", selection); 
        }
    }
}