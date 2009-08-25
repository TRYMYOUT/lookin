// WATCHER
//
// UI.InformationDisclosure.ConfigPanel.cs
// Main implementation of Information Disclosure Config Panel.
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
    public partial class StringCheckConfigPanel : UserControl
    {
        WatcherCheck watchercheck;

        public StringCheckConfigPanel()
        {
            InitializeComponent();
        }

        public StringCheckConfigPanel(WatcherCheck check)
        {
            InitializeComponent();
            watchercheck = check;
        }

        public void Init(String[] defaultstrings, String boxtitle, String entrytitle)
        {
            string configstring;
            if (defaultstrings != null)
            {
                for (int i = 0; i < defaultstrings.Length; i++)
                {
                    defaultstrings[i] = Watcher.Utility.Base64Encode(defaultstrings[i]);
                }
                configstring = WatcherEngine.Configuration.GetCheckConfig(watchercheck, "stringcheckList", (String)String.Join(",", defaultstrings));
            }
            else
            {
                configstring = WatcherEngine.Configuration.GetCheckConfig(watchercheck, "stringcheckList");
            }
            if (configstring != null)
            {
                char[] splitter = new char[1];
                splitter[0] = ',';
                string[] errorlist = configstring.Split(splitter);
                this.stringchecklistBox.BeginUpdate();
                for (int i = 0; i < errorlist.Length; i++)
                {
                    //Items are stored encoded
                    ListViewItem message = new ListViewItem(Watcher.Utility.Base64Decode(errorlist[i]));
                    this.stringchecklistBox.Items.Add(message);
                    this.stringchecklistBox.Text = "";
                }
            }
            lblReplacementStrings.Text = boxtitle;
            lblReplacementString.Text = entrytitle;
            this.stringchecklistBox.EndUpdate();
        }

        private void addbutton_Click(object sender, EventArgs e)
        {
            string stringcheckMessageText = this.stringcheckentrytextBox.Text.Trim();
            
            if (stringcheckMessageText.Length <= 0)
                return;

            ListViewItem message = new ListViewItem(stringcheckMessageText);

            this.stringchecklistBox.BeginUpdate();
            
            // skip duplicates
            if (!this.stringchecklistBox.Items.Contains(message))
            {
                this.stringchecklistBox.Items.Add(message);
                this.stringchecklistBox.Text = "";
            }
            else
            {
                MessageBox.Show("\"" + stringcheckMessageText + "\" is already in the word list", "Error");
            }

            this.stringchecklistBox.EndUpdate();
            
            List<string> tempstring = new List<string>();
            foreach (ListViewItem item in this.stringchecklistBox.Items)
            {
                tempstring.Add(Watcher.Utility.Base64Encode(item.Text));
            }
            WatcherEngine.Configuration.SetCheckConfig(watchercheck, "stringcheckList", (String) String.Join(",", tempstring.ToArray()));

            this.stringcheckentrytextBox.Text = "";
            watchercheck.UpdateWordList();
        }

        private void deletebutton_Click(object sender, EventArgs e)
        {
            if (this.stringchecklistBox.SelectedItems.Count < 0)
            {
                MessageBox.Show("You must select a domain to remove from the trusted domain list", "Error");
                return;
            }

            this.stringchecklistBox.BeginUpdate();
            foreach (ListViewItem item in this.stringchecklistBox.SelectedItems)
            {
                this.stringchecklistBox.Items.Remove(item);
            }
            this.stringchecklistBox.EndUpdate();
            
            List<string> tempstring = new List<string>();
            foreach (ListViewItem item in this.stringchecklistBox.Items)
            {
                tempstring.Add(Watcher.Utility.Base64Encode(item.Text));
            }
            WatcherEngine.Configuration.SetCheckConfig(watchercheck, "stringcheckList", String.Join(",", tempstring.ToArray()));
            watchercheck.UpdateWordList();
        }
    }
}
