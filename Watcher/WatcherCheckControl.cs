// WATCHER
//
// WatcherConfig.cs
// Main implementation of WatcherConfig UI.
//
// Copyright (c) 2010 Casaba Security, LLC
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
    public partial class WatcherCheckControl : UserControl
    {
        #region Fields
        private UpdateManager _versionCheck = new UpdateManager();     // This class performs logic related to product updates. 
        #endregion

        #region Ctor(s)
        public WatcherCheckControl()
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
                // Add the available checks to the list box and set their enabled/disabled status accordingly.
                InitializeCheckListBox();
            }
            int index = this.copyrightlabel.Text.IndexOf(",");
            Version currentver = new UpdateManager().CurrentVersionEngine;
            this.copyrightlabel.Text = this.copyrightlabel.Text.Insert(index, " v" + currentver.ToString());
                
            this.enabledChecksListView.ItemChecked += new System.Windows.Forms.ItemCheckedEventHandler(this.checkenableListBox_ItemCheck);

            //this.enabledChecksListView.Columns[0].AutoResize(ColumnHeaderAutoResizeStyle.HeaderSize);
            //this.enabledChecksListView.Columns[lastIndex].Width = 255;

            base.OnLoad(e);
        }

        #endregion

        #region Private Method(s)

        /// <summary>
        /// Add each available check to the list box and enable/disable it accordingly.
        /// </summary>
        private void InitializeCheckListBox()
        {
            enabledChecksListView.BeginUpdate();

            // Enumerate the available checks
            foreach (WatcherCheck check in WatcherEngine.CheckManager.Checks)
            {
                ListViewItem item = new ListViewItem();

                // Create a new list item for each check
                item.Tag = check;
                item.Text = check.ToString();
                item.Checked = check.Enabled;

                // Add the display-worthy (and globalizable) list of standards of which the current check complies, to the 
                // appropriate column of the item.
                item.SubItems.Add(check.GetStandardsComplianceString());

                // Add the item to the list of checks
                enabledChecksListView.Items.Add(item);
            }

            enabledChecksListView.AutoResizeColumns(ColumnHeaderAutoResizeStyle.ColumnContent);
            enabledChecksListView.EndUpdate();
        }

        /// <summary>
        /// Scan through each check after a click and update the enabled/disabled state.
        /// </summary>
        private void checkenableListBox_ItemCheck(object sender, EventArgs e)
        {
            bool isCheckEnabled;
            for (int i = 0; i < enabledChecksListView.Items.Count; i++)
            {
                isCheckEnabled = enabledChecksListView.Items[i].Checked;

                // Cast the List Box item to a Watcher Check
                WatcherCheck check = enabledChecksListView.Items[i].Tag as WatcherCheck;
                if (check == null)
                {
                    String errorMessage = "ListView item referenced is not a WatcherCheck.";
                    Trace.TraceError("Error: {0}", errorMessage);
                    Debug.Assert(false, errorMessage);
                    return;
                }

                // TODO: Have the configuration persist the check Enabled settings
                // Update the check configuration
                ((WatcherCheck)enabledChecksListView.Items[i].Tag).Enabled = isCheckEnabled;
                WatcherEngine.Configuration.SetCheckEnabledConfig(check);

                int index = WatcherEngine.CheckManager.Checks.IndexOf(check);
                WatcherEngine.CheckManager.Checks[index]._enabled = isCheckEnabled;
            }
        }

        /// <summary>
        /// Updates UI when a check is clicked on.
        /// </summary>
        private void enabledChecksListView_SelectedIndexChanged(object sender, EventArgs e)
        {
            // No need to continue processing this event if there are no items selected
            if (enabledChecksListView.SelectedItems.Count < 1)
            {
                Debug.Print("EnabledChecksListView_SelectedIndexChanged event fired, but no items were selected.");
                return;
            }

            domainconfigButton.Visible = true;
            checklistsplitContainer.Panel2.SuspendLayout();
            checklistsplitContainer.Panel2.Controls.Clear();
           
            // Retrieve the check object from the user-data associated with the item
            WatcherCheck check = (WatcherCheck)enabledChecksListView.SelectedItems[0].Tag;

            RichTextBox description = new RichTextBox();

            description.SuspendLayout();
            //description.BackColor = System.Drawing.SystemColors.GradientInactiveCaption;
            //description.BackColor = System.Drawing.SystemColors.Control;
            description.BackColor = WatcherEngine.UI.watcherResultsTab.BackColor;
            description.BorderStyle = BorderStyle.None;
            description.Multiline = true;
            description.Margin = new System.Windows.Forms.Padding(3, 10, 3, 10);
            description.Dock = DockStyle.Fill;  // Default to filling the entire panel (in the event that there is no configuration)
            description.DetectUrls = true;
            description.ScrollBars = RichTextBoxScrollBars.Vertical;
            description.Text = check.GetDescription();
            description.WordWrap = true;
            description.Font = new System.Drawing.Font("Microsoft Sans Serif", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            //description.Height = description.GetLineFromCharIndex(description.Text.Length) + 1 * description.Font.Height + 1 + description.Margin.Vertical;
            description.Height = 130;
            // Display the configuration options for this check if they exist
            Panel panelCheckConfiguration = check.GetConfigPanel();
            if (panelCheckConfiguration != null)
            {
                // Prepare to display the check configuration
                panelCheckConfiguration.SuspendLayout();
                panelCheckConfiguration.Dock = DockStyle.Fill;
                panelCheckConfiguration.AutoScroll = true;
                // Setup scroll bars for when the display is too small
                panelCheckConfiguration.AutoScrollMinSize = new System.Drawing.Size(500, 250);
                panelCheckConfiguration.Padding = new System.Windows.Forms.Padding(0, 10, 0, 0);

                // Add the configuration options to the bottom panel of the check list tab
                checklistsplitContainer.Panel2.Controls.Add(panelCheckConfiguration);
                panelCheckConfiguration.ResumeLayout();

                // Since a configuration panel exists, we'll need to adjust the location of the description
                description.Dock = DockStyle.Top;
            }

            // Add the check description to the bottom panel of the check list tab
            checklistsplitContainer.Panel2.Controls.Add(description);
            description.ResumeLayout();

            // Display the check's description/configuration panel
            checklistsplitContainer.Panel2.ResumeLayout();
            checklistsplitContainer.Panel2.Show();
        }

        /// <summary>
        /// Display subset of checks based on text provided by users
        /// </summary>
        private void filtertextBox_TextChanged(object sender, EventArgs e)
        {
            enabledChecksListView.BeginUpdate();
            enabledChecksListView.Items.Clear();

            foreach (WatcherCheck check in WatcherEngine.CheckManager.Checks)
            {
                String checkName = check.GetName();

                if (checkName.IndexOf(filtertextBox.Text, StringComparison.CurrentCultureIgnoreCase) > -1)
                {
                    ListViewItem item = new ListViewItem();

                    // Create a new list item for each check
                    item.Tag = check;
                    item.Text = check.ToString();
                    item.Checked = check.Enabled;

                    // Add the display-worthy (and globalizable) list of standards of which the current check complies, to the 
                    // appropriate column of the item.
                    item.SubItems.Add(check.GetStandardsComplianceString());

                    // Add the item to the list of checks
                    enabledChecksListView.Items.Add(item);
                }
            }
            enabledChecksListView.EndUpdate();
        }

        /// <summary>
        /// TODO:.
        /// </summary>
        private void domainconfigButton_Click(object sender, EventArgs e)
        {
            domainconfigButton.Visible = false;
            //checklistgroupBox.Dock = DockStyle.None;
            //checklistgroupBox.Anchor = AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Top | AnchorStyles.Bottom;
            ////checklistgroupBox.AutoSize = false;
            //checklistgroupBox.Width = configGroupBox.Width; // TODO: Why is this required?? The control does does not anchor properly for some reason after restoring the view.
            ////checklistgroupBox.Height = configGroupBox.Height - 3; // TODO: Why is this required?? The control does not anchor properly for some reason after restoring the view.
            //checklistgroupBox.Refresh();
        }

        /// <summary>
        /// Enable all checks.
        /// </summary>
        private void labelEnableAll_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            for (int i = 0; i < enabledChecksListView.Items.Count; i++)
            {
                // Cast the List Box item to a Watcher Check
                WatcherCheck check = enabledChecksListView.Items[i].Tag as WatcherCheck;
                if (check == null)
                {
                    String errorMessage = "ListView item referenced is not a WatcherCheck.";
                    Trace.TraceError("Error: {0}", errorMessage);
                    Debug.Assert(false, errorMessage);
                    return;
                }

                // TODO: Have the configuration persist the check Enabled settings
                // Update the check configuration
                ((WatcherCheck)enabledChecksListView.Items[i].Tag).Enabled = true;
                enabledChecksListView.Items[i].Checked = true;
                WatcherEngine.Configuration.SetCheckEnabledConfig(check);

                int index = WatcherEngine.CheckManager.Checks.IndexOf(check);
                WatcherEngine.CheckManager.Checks[index]._enabled = true;
            }
        }

        /// <summary>
        /// Disable all checks
        /// </summary>
        private void labelDisableAll_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            for (int i = 0; i < enabledChecksListView.Items.Count; i++)
            {
                // Cast the List Box item to a Watcher Check
                WatcherCheck check = enabledChecksListView.Items[i].Tag as WatcherCheck;
                if (check == null)
                {
                    String errorMessage = "ListView item referenced is not a WatcherCheck.";
                    Trace.TraceError("Error: {0}", errorMessage);
                    Debug.Assert(false, errorMessage);
                    return;
                }

                // TODO: Have the configuration persist the check Enabled settings
                // Update the check configuration
                ((WatcherCheck)enabledChecksListView.Items[i].Tag).Enabled = false;
                enabledChecksListView.Items[i].Checked = false;
                WatcherEngine.Configuration.SetCheckEnabledConfig(check);

                int index = WatcherEngine.CheckManager.Checks.IndexOf(check);
                WatcherEngine.CheckManager.Checks[index]._enabled = false;
            }
            domainconfigButton_Click(sender, e);
        }

        /// <summary>
        /// This event handler opens a new Explorer window and visits the Casaba homepage.
        /// </summary>
        /// <remarks>Failures are "sort of" swallowed here, i.e. a browser may never open if one of the exceptions below is thrown.</remarks>
        private void linkLabel_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            try
            {
                // Show the link was visited and go to our URL
                e.Link.Visited = true;
                System.Diagnostics.Process.Start("http://www.casabasecurity.com/");
            }

            catch (Win32Exception ex)
            {
                // Thrown when the process returns a Win32 error code
                Trace.TraceError("Unable to launch web site: {0}", ex.Message);
            }

            catch (FileNotFoundException ex)
            {
                // Thrown when an attempt to access a file that does not exist on disk is made
                Trace.TraceError("Unable to launch web site: {0}", ex.Message);
            }
        }

        #endregion

        private void checklistsplitContainer_Panel2_Paint(object sender, PaintEventArgs e)
        {

        }

    }
}