// WATCHER
//
// Check.Pasv.InformationDisclosure.ConfigPanel.cs
//
// Copyright (c) 2009 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Data;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace WatcherCheckLib
{
    public partial class StringCheckConfigPanel : UserControl
    {
        WatcherEngine.WatcherCheck watchercheck;

        public StringCheckConfigPanel()
        {
            InitializeComponent();
        }

        public StringCheckConfigPanel(WatcherEngine.WatcherCheck check)
        {
            InitializeComponent();
            watchercheck = check;
        }

        public void Init(String[] defaultstrings, String boxtitle, String entrytitle)
        {
            for (int i = 0; i < defaultstrings.Length; i++)
            {
                defaultstrings[i] = WatcherEngine.Watcher.Base64Encode(defaultstrings[i]);
            }
            string configstring = WatcherEngine.Watcher.GetCheckConfig(watchercheck, "stringcheckList", (String) String.Join(",", defaultstrings.ToArray()));
            char[] splitter = new char[1];
            splitter[0] = ',';
            string[] errorlist = configstring.Split(splitter);
            this.stringchecklistBox.BeginUpdate();
            for (int i = 0; i < errorlist.Length; i++)
            {
                //Items are stored encoded
                ListViewItem message = new ListViewItem(WatcherEngine.Watcher.Base64Decode(errorlist[i]));
                this.stringchecklistBox.Items.Add(message);
                this.stringchecklistBox.Text = "";
            }
            groupBox1.Text = boxtitle;
            stringcheckgroupBox.Text = entrytitle;
            this.stringchecklistBox.EndUpdate();
        }

        private void stringcheckListBox_SelectedIndexChanged(object sender, EventArgs e)
        {

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
                MessageBox.Show("\"" + stringcheckMessageText + "\" is already in the database error list", "Error");
            }

            this.stringchecklistBox.EndUpdate();
            
           
            List<string> tempstring = new List<string>();
            foreach (ListViewItem item in this.stringchecklistBox.Items)
            {
                tempstring.Add(WatcherEngine.Watcher.Base64Encode(item.Text));
            }
            WatcherEngine.Watcher.SetCheckConfig(watchercheck, "stringcheckList", (String) String.Join(",", tempstring.ToArray()));

            watchercheck.UpdateWordList();
        }

        private void deletebutton_Click(object sender, EventArgs e)
        {
            if (this.stringchecklistBox.SelectedItems.Count < 0)
            {
                MessageBox.Show("You must select a domain to delete from the trusted domain list", "Error");
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
                tempstring.Add(WatcherEngine.Watcher.Base64Encode(item.Text));
            }
            WatcherEngine.Watcher.SetCheckConfig(watchercheck, "stringcheckList", String.Join(",", tempstring.ToArray()));
            watchercheck.UpdateWordList();
        }
    }
}
