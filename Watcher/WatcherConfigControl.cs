// WATCHER
//
// WatcherConfig.cs
// Main implementation of WatcherConfig UI.
//
// Copyright (c) 2009 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Collections.Generic;
using System.Configuration;
using System.ComponentModel;
using System.Diagnostics;
using System.Data;
using System.IO;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace CasabaSecurity.Web.Watcher
{
    /// <summary>
    /// This class implements the Watcher Configuration tab.
    /// </summary>
    public partial class WatcherConfigControl : UserControl
    {
        #region Fields
        private UpdateManager _versionCheck = new UpdateManager();     // This class performs logic related to product updates. 
        #endregion

        #region Ctor(s)
        public WatcherConfigControl()
        {
            InitializeComponent();
        }
        #endregion

        #region Protected Method(s)

        /// <summary>
        /// This method initializes the control values prior to displaying the control.
        /// </summary>
        /// <remarks>
        /// This event occurs before the control becomes visible for the first time (ref: MSDN).
        /// </remarks>
        protected override void OnLoad(EventArgs e)
        {
            // Don't load the configuration in design mode
            if (this.Site == null || this.Site.DesignMode == false)
            {
                // Set the Watcher Enabled check box and Origin Domain text
                this.enableCheckBox.Checked = WatcherEngine.Configuration.Enabled;
                this.originDomainTextBox.Text = WatcherEngine.Configuration.OriginDomain;
                this.autosavecheckBox.Checked = WatcherEngine.Configuration.AutoSave;
                this.autovercheckBox.Checked = WatcherEngine.Configuration.AutoVerCheck;

                // Add the Trusted Domains from the configuration to the TD list view.
                InitializeTrustedDomainList();

                // Check for new version of Watcher if AutoCheck is enabled
                if (WatcherEngine.Configuration.AutoVerCheck)
                {
                    _versionCheck.CheckForUpdate(false);
                }
                int index = this.copyrightlabel.Text.IndexOf(",");
                Version currentver = new UpdateManager().CurrentVersionEngine;
                this.copyrightlabel.Text = this.copyrightlabel.Text.Insert(index, " v" + currentver.ToString());
                // Add the available checks to the list box and set their enabled/disabled status accordingly.
//                InitializeCheckListBox();
            }

            //this.enabledChecksListView.Columns[0].AutoResize(ColumnHeaderAutoResizeStyle.HeaderSize);
            //this.enabledChecksListView.Columns[lastIndex].Width = 255;

            base.OnLoad(e);
        }

        #endregion

        #region Private Method(s)

        /// <summary>
        /// This method clears the Trusted Domain list view and populates it with the Trusted Domains
        /// from the configuration.
        /// </summary>
        private void InitializeTrustedDomainList()
        {
            trustedDomainListBox.BeginUpdate();
            
            // Clear the Trusted Domain list box and add the configured trusted domains
            trustedDomainListBox.Items.Clear();
            foreach (String domain in WatcherEngine.Configuration.TrustedDomains)
            {
                ListViewItem item = new ListViewItem(domain);
                trustedDomainListBox.Items.Add(item);
            }

            trustedDomainListBox.EndUpdate();
        }

//        /// <summary>
//        /// Add each available check to the list box and enable/disable it accordingly.
//        /// </summary>
//        private void InitializeCheckListBox()
//        {
//            enabledChecksListView.BeginUpdate();

//            // Enumerate the available checks
//            foreach (WatcherCheck check in WatcherEngine.CheckManager.Checks)
//            {
//                ListViewItem item = new ListViewItem();

//                // Create a new list item for each check
//                item.Tag = check;
//                item.Text = check.ToString();
//                item.Checked = check.Enabled;

//                // Add the display-worthy (and globalizable) list of standards of which the current check complies, to the 
//                // appropriate column of the item.
//                item.SubItems.Add(check.GetStandardsComplianceString());

//                // Add the item to the list of checks
//                //enabledChecksListView.Items.Add(item);
//            }

//            enabledChecksListView.AutoResizeColumns(ColumnHeaderAutoResizeStyle.ColumnContent);
//            enabledChecksListView.EndUpdate();
//        }

        ///// <summary>
        ///// Scan through each check after a click and update the enabled/disabled state.
        ///// </summary>
        //private void checkenableListBox_ItemCheck(object sender, EventArgs e)
        //{
        //    bool isCheckEnabled;
        //    for (int i = 0; i < enabledChecksListView.Items.Count; i++)
        //    {
        //        isCheckEnabled = enabledChecksListView.Items[i].Checked;

        //        // Cast the List Box item to a Watcher Check
        //        WatcherCheck check = enabledChecksListView.Items[i].Tag as WatcherCheck;
        //        if (check == null)
        //        {
        //            String errorMessage = "ListView item referenced is not a WatcherCheck.";
        //            Trace.TraceError("Error: {0}", errorMessage);
        //            Debug.Assert(false, errorMessage);
        //            return;
        //        }

        //        // TODO: Have the configuration persist the check Enabled settings
        //        // Update the check configuration
        //        ((WatcherCheck)enabledChecksListView.Items[i].Tag).Enabled = isCheckEnabled;
        //        WatcherEngine.Configuration.SetCheckEnabledConfig(check);

        //        int index = WatcherEngine.CheckManager.Checks.IndexOf(check);
        //        WatcherEngine.CheckManager.Checks[index]._enabled = isCheckEnabled;
        //    }
        //}

        ///// <summary>
        ///// Updates UI when a check is clicked on.
        ///// </summary>
        //private void enabledChecksListView_SelectedIndexChanged(object sender, EventArgs e)
        //{
        //    // No need to continue processing this event if there are no items selected
        //    if (enabledChecksListView.SelectedItems.Count < 1)
        //    {
        //        Debug.Print("EnabledChecksListView_SelectedIndexChanged event fired, but no items were selected.");
        //        return;
        //    }

        //    configGroupBox.Visible = false;
        //    enablegroupBox.Visible = false;
        //    domainconfigButton.Visible = true;
        //    checklistgroupBox.Dock = DockStyle.Fill;

        //    checklistsplitContainer.Panel2.Controls.Clear();
        //    checklistsplitContainer.Panel2.SuspendLayout();

        //    // Retrieve the check object from the user-data associated with the item
        //    WatcherCheck check = (WatcherCheck)enabledChecksListView.SelectedItems[0].Tag;
            
        //    RichTextBox description = new RichTextBox();
        //    description.SuspendLayout();
        //    description.BackColor = Control.DefaultBackColor;
        //    description.BorderStyle = BorderStyle.Fixed3D;
        //    description.Multiline = true;
        //    description.Margin = new System.Windows.Forms.Padding(3, 0, 3, 0);
        //    description.Dock = DockStyle.Top;
        //    description.DetectUrls = true;
        //    description.Height = 80;
        //    description.ScrollBars = RichTextBoxScrollBars.Vertical;
        //    description.Text = check.GetDescription();
        //    description.LinkClicked += new LinkClickedEventHandler(this.richTextBox1_LinkClicked);
        //    description.WordWrap = true;
        //    description.ResumeLayout();

        //    Panel checkpanel = check.GetConfigPanel();
        //    checkpanel.Dock = DockStyle.Fill;

        //    checklistsplitContainer.Panel2.Controls.Add(checkpanel);
        //    checklistsplitContainer.Panel2.Controls.Add(description);
            
        //    checklistsplitContainer.Panel2.ResumeLayout();
        //    checklistsplitContainer.Panel2.Show();
        //}

        ///// <summary>
        ///// This event is triggered when the Origin Domain text box is modified.
        ///// </summary>
        //private void originDomainTextBox_TextChanged(object sender, EventArgs e)
        //{
        //    WatcherEngine.Configuration.OriginDomain = this.originDomainTextBox.Text;

        //    if (this.originDomainTextBox.Text.Contains("casabasecurity.com") || this.originDomainTextBox.Text.Contains("nottrusted.com"))
        //    {
        //        this.casabapictureBox.Visible = true;
        //    }
        //    else
        //    {
        //        this.casabapictureBox.Visible = false;
        //    }
        //}

        /// <summary>
        /// This method adds the specified Trusted Domain to the Trusted Domain List View.
        /// </summary>
        private void AddTrustedDomainButton_Click(object sender, EventArgs e)
        {
            // Make sure the user entered -something-
            // TODO: Validate this entry
            String trustedDomain = this.trustedDomainTextBox.Text.Trim();
            if (trustedDomain.Length == 0)
            {
                Trace.TraceWarning("Warning: Not adding zero-length item to Trusted Domain list.");
                goto done;
            }

            // Don't add duplicate Trusted Domains
            ListViewItem domain = new ListViewItem(trustedDomain);
            if (this.trustedDomainListBox.Items.Contains(domain))
            {
                Trace.TraceWarning("Warning: Trusted Domain already exists in the list.");
                MessageBox.Show(String.Format("The domain \"{0}\" is already in the Trusted Domains list.", trustedDomain), "Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                goto done;
            }

            // Add the new Trusted Domain to the List View
            trustedDomainListBox.BeginUpdate();
            trustedDomainListBox.Items.Add(domain);
            trustedDomainListBox.EndUpdate();

            // Add the new Trusted Domain to the configuration
            WatcherEngine.Configuration.TrustedDomains.Add(trustedDomain);

            if (WatcherEngine.Configuration.AutoSave)
            {
                WatcherEngine.Configuration.Save();
            }
            // Clear the text entered by the user
            trustedDomainTextBox.Text = "";
done:
            base.OnClick(e);
        }

        /// <summary>
        /// Clear the selected items from the Trusted Domains List View.
        /// </summary>
        private void ClearDomainButton_Click(object sender, EventArgs e)
        {
            // Make sure the user selected a Trusted Domain to delete
            if (this.trustedDomainListBox.SelectedItems.Count < 0)
            {
                MessageBox.Show("You must select an item to remove.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            // Remove the selected items from the list box and configuration
            this.trustedDomainListBox.BeginUpdate();
            foreach (ListViewItem item in this.trustedDomainListBox.SelectedItems)
            {
                // Remove from the list box
                this.trustedDomainListBox.Items.Remove(item);

                // Remove from the configuration
                if (WatcherEngine.Configuration.TrustedDomains.Remove(item.Text) == false)
                {
                    String errorMessage = String.Format("Failed to find \"{0}\" in configuration's trusted domain list.", item.Text);
                    Debug.Assert(false, errorMessage);
                    Trace.TraceError("Error: {0}", errorMessage);
                }
            }
            this.trustedDomainListBox.EndUpdate();

            if (WatcherEngine.Configuration.AutoSave)
            {
                WatcherEngine.Configuration.Save();
            }

            base.OnClick(e);
        }

        /// <summary>
        /// Enable/Disable the config options when Watcher is enabled/disabled
        /// </summary>
        private void enableCheckBox_CheckedChanged(object sender, EventArgs e)
        {
            WatcherEngine.Configuration.Enabled = this.enableCheckBox.Checked;
            if (this.enableCheckBox.Checked)
            {
                this.configGroupBox.Enabled = true;
                this.appgroupBox.Enabled = true;
//                this.checklistgroupBox.Enabled = true;
            }
            else
            {
                this.configGroupBox.Enabled = false;
                this.appgroupBox.Enabled = false;
//                this.checklistgroupBox.Enabled = false;
            }
        }

        /// <summary>
        /// Save configuration on UI click.
        /// </summary>
        private void saveconfigbutton_Click(object sender, EventArgs e)
        {
            // TODO: hack because eventhandler is not always getting called
//            checkenableListBox_ItemCheck(this, new EventArgs());
            
            // TODO: Display an error if this fails
            WatcherEngine.Configuration.Save();
            MessageBox.Show("Configuration successfully saved.", "Save Configuration", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        /// <summary>
        /// This method checks for updates to Watcher.
        /// </summary>
        private void CheckLatestButton_Click_1(object sender, EventArgs e)
        {
            _versionCheck.CheckForUpdate();
            base.OnClick(e);
        }

        /// <summary>
        /// This method allows links in the description text.
        /// </summary>
        private void richTextBox1_LinkClicked(object sender, System.Windows.Forms.LinkClickedEventArgs e)
        {
            System.Diagnostics.Process.Start(e.LinkText);
        } 

        /// <summary>
        /// Visit the Casaba Security web site.
        /// </summary>
        private void linkLabel_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            try
            {
                e.Link.Visited = true;
                System.Diagnostics.Process.Start("http://www.casabasecurity.com/");
            }

            catch (Win32Exception ex)
            {
                // Thrown when a Win32 error code is returned
                Trace.TraceError("Error: Win32Exception: {0}", ex.Message);
            }

            catch (ObjectDisposedException ex)
            {
                // Thrown when an operation is performed on a disposed object
                Trace.TraceError("Error: ObjectDisposedException: {0}", ex.Message);
            }

            catch (FileNotFoundException ex)
            {
                // Thrown when the resource does not exist
                Trace.TraceError("Error: FileNotFoundException: {0}", ex.Message);
            }
        }

        ///// <summary>
        ///// Display subset of checks based on text provided by users
        ///// </summary>
        //private void filtertextBox_TextChanged(object sender, EventArgs e)
        //{
        //    enabledChecksListView.BeginUpdate();
        //    enabledChecksListView.Items.Clear();

        //    foreach (WatcherCheck check in WatcherEngine.CheckManager.Checks)
        //    {
        //        String checkName = check.GetName();

        //        if (checkName.IndexOf(filtertextBox.Text, StringComparison.CurrentCultureIgnoreCase) > -1)
        //        {
        //            ListViewItem item = new ListViewItem();

        //            // Create a new list item for each check
        //            item.Tag = check;
        //            item.Text = check.ToString();
        //            item.Checked = check.Enabled;

        //            // Add the display-worthy (and globalizable) list of standards of which the current check complies, to the 
        //            // appropriate column of the item.
        //            item.SubItems.Add(check.GetStandardsComplianceString());

        //            // Add the item to the list of checks
        //            enabledChecksListView.Items.Add(item);
        //        }
        //    }
        //    enabledChecksListView.EndUpdate();
        //}

        /// <summary>
        /// TODO:.
        /// </summary>
        private void domainconfigButton_Click(object sender, EventArgs e)
        {
            //enablegroupBox.Visible = true;
            configGroupBox.Visible = true;
            //domainconfigButton.Visible = false;
            //checklistgroupBox.Dock = DockStyle.None;
            //checklistgroupBox.Anchor = AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Top | AnchorStyles.Bottom;
            ////checklistgroupBox.AutoSize = false;
            //checklistgroupBox.Width = configGroupBox.Width; // TODO: Why is this required?? The control does does not anchor properly for some reason after restoring the view.
            ////checklistgroupBox.Height = configGroupBox.Height - 3; // TODO: Why is this required?? The control does not anchor properly for some reason after restoring the view.
            //checklistgroupBox.Refresh();
        }

        private void autosavecheckBox_CheckedChanged(object sender, EventArgs e)
        {
            WatcherEngine.Configuration.AutoSave = this.autosavecheckBox.Checked;
        }

        private void autovercheckbox_CheckedChanged(object sender, EventArgs e)
        {
            WatcherEngine.Configuration.AutoVerCheck = this.autovercheckBox.Checked;
        }

        private void originDomainTextBox_TextChanged(object sender, EventArgs e)
        {
            WatcherEngine.Configuration.OriginDomain = originDomainTextBox.Text;
        }


        ///// <summary>
        ///// Enable all checks.
        ///// </summary>
        //private void labelEnableAll_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        //{
        //    for (int i = 0; i < enabledChecksListView.Items.Count; i++)
        //    {
        //        // Cast the List Box item to a Watcher Check
        //        WatcherCheck check = enabledChecksListView.Items[i].Tag as WatcherCheck;
        //        if (check == null)
        //        {
        //            String errorMessage = "ListView item referenced is not a WatcherCheck.";
        //            Trace.TraceError("Error: {0}", errorMessage);
        //            Debug.Assert(false, errorMessage);
        //            return;
        //        }

        //        // TODO: Have the configuration persist the check Enabled settings
        //        // Update the check configuration
        //        ((WatcherCheck)enabledChecksListView.Items[i].Tag).Enabled = true;
        //        enabledChecksListView.Items[i].Checked = true;
        //        WatcherEngine.Configuration.SetCheckEnabledConfig(check);

        //        int index = WatcherEngine.CheckManager.Checks.IndexOf(check);
        //        WatcherEngine.CheckManager.Checks[index]._enabled = true;
        //    }
        //}

        ///// <summary>
        ///// Disable all checks
        ///// </summary>
        //private void labelDisableAll_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        //{
        //    for (int i = 0; i < enabledChecksListView.Items.Count; i++)
        //    {
        //        // Cast the List Box item to a Watcher Check
        //        WatcherCheck check = enabledChecksListView.Items[i].Tag as WatcherCheck;
        //        if (check == null)
        //        {
        //            String errorMessage = "ListView item referenced is not a WatcherCheck.";
        //            Trace.TraceError("Error: {0}", errorMessage);
        //            Debug.Assert(false, errorMessage);
        //            return;
        //        }

        //        // TODO: Have the configuration persist the check Enabled settings
        //        // Update the check configuration
        //        ((WatcherCheck)enabledChecksListView.Items[i].Tag).Enabled = false;
        //        enabledChecksListView.Items[i].Checked = false;
        //        WatcherEngine.Configuration.SetCheckEnabledConfig(check);

        //        int index = WatcherEngine.CheckManager.Checks.IndexOf(check);
        //        WatcherEngine.CheckManager.Checks[index]._enabled = false;
        //    }
        //    this.enableCheckBox.Checked = false;
        //    domainconfigButton_Click(sender, e);
        //}

        #endregion
    }
}