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

                //Set Background Color as configured
                WatcherEngine.UI.watcherConfigTab.BackColor = WatcherEngine.Configuration.BackGroundColor;
                WatcherEngine.UI.watcherCheckTab.BackColor = WatcherEngine.Configuration.BackGroundColor;
                WatcherEngine.UI.watcherResultsTab.BackColor = WatcherEngine.Configuration.BackGroundColor;

                // Add the Trusted Domains from the configuration to the TD list view.
                InitializeTrustedDomainList();

                // Check for new version of Watcher if AutoCheck is enabled
                if (WatcherEngine.Configuration.AutoVerCheck)
                {
                    _versionCheck.CheckForUpdate(false);
                }
                int index = copyrightlabel.Text.IndexOf(",");
                Version currentver = new UpdateManager().CurrentVersionEngine;
                this.copyrightlabel.Text = copyrightlabel.Text.Insert(index, " v" + currentver.ToString());
                // Add the available checks to the list box and set their enabled/disabled status accordingly.
                //InitializeCheckListBox();

                InitializeOutputPlugins();
            }

            //this.enabledChecksListView.Columns[0].AutoResize(ColumnHeaderAutoResizeStyle.HeaderSize);
            //this.enabledChecksListView.Columns[lastIndex].Width = 255;

            base.OnLoad(e);
        }

        #endregion

        #region Private Method(s)

        /// <summary>
        /// This method loads the available output plugins, presents any configuration panels, and
        /// displays any errors that occurred during the load.
        /// </summary>
        private void InitializeOutputPlugins()
        {
            // Load the output plugins and add any associated configuration panel to the Watcher
            // configuration tab.
            foreach (WatcherOutputPlugin plugin in WatcherEngine.OutputPluginManager.OutputPlugins)
            {
                pluginPanel.Controls.Add(plugin.GetConfigPanel());
            }

            // Display any error message associated with loading the plugins
            // TODO: allow multiple error messages; currently, last error message will overwrite all previous
            if (WatcherEngine.OutputPluginManager.ErrorMessage.Length > 0)
            {
                WarningDialog dlg = new WarningDialog();
                dlg.Text = WatcherEngine.OutputPluginManager.ErrorMessage;
                dlg.ShowDialog(this);
            }

            // Automatically size the panel based on the configuration panels added
            pluginPanel.AutoSize = true;
        }

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
                this.pluginPanel.Enabled = true;
//                this.checklistgroupBox.Enabled = true;
            }
            else
            {
                this.configGroupBox.Enabled = false;
                this.appgroupBox.Enabled = false;
                this.pluginPanel.Enabled = false;
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
                System.Diagnostics.Process.Start("http://www.casaba.com/");
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

        private void button1_Click(object sender, EventArgs e)
        {
            colorDialog.ShowDialog();
            //WatcherEngine.UI.BackColor = colorDialog.Color;
            WatcherEngine.UI.watcherConfigTab.BackColor = colorDialog.Color;
            WatcherEngine.UI.watcherCheckTab.BackColor = colorDialog.Color;
            WatcherEngine.UI.watcherResultsTab.BackColor = colorDialog.Color;
            WatcherEngine.Configuration.BackGroundColor = colorDialog.Color;
            
        }

        #endregion

        private void uigroupBox_Enter(object sender, EventArgs e)
        {

        }

        private void copyrightlabel_Click(object sender, EventArgs e)
        {

        }

        private void pnlCopyright_Paint(object sender, PaintEventArgs e)
        {

        }

        #region Private Callback(s)

        /// <summary>
        /// This delegate is used to process sessions offline, like in the case of
        /// someone loading a .SAZ (session archive) file.
        /// </summary>
        private delegate void ProcessOfflineSessions();

        #endregion

        /// <summary>
        /// Setup a separate thread to process offline session data on asynchronously.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void ProcessOffline_Click(object sender, EventArgs e)
        {
            // Use a delegate to perform the operation asynchronously--since we're doing network IO,
            // this wastes a thread for the sake of simplicity.
            ProcessOfflineSessions callback = ProcessSessions;

            // Invoke the update check asynchronously
            callback.BeginInvoke(

                // This is the callback method
                delegate(IAsyncResult ar)
                {
                    try
                    {
                        WatcherEngine.ProgressDialog.Show();
                        // Tidy up after the update check
                        ProcessOfflineSessions _callback = (ProcessOfflineSessions)ar.AsyncState;
                        _callback.EndInvoke(ar); // TODO: this will throw any exceptions that happened during the call
                    }
                    catch (WatcherException ex)
                    {
                        Trace.TraceError("Exception: {0}", ex.Message);
                        return;
                    }
                    finally
                    {
                        // Inform the user of progress
                        WatcherEngine.ProgressDialog.Hide();
                    }

                },

                // This is the AsyncState seen in the callback method above
                callback);
        }

        /// <summary>
        /// Get all of the sessions in the session list and process them through Watcher's check engine
        /// one at a time.  Useful for processing sessions stored in a .SAZ file or otherwise when offline.
        /// </summary>
        public void ProcessSessions()
        {
            Fiddler.Session[] sessions = Fiddler.FiddlerApplication.UI.GetAllSessions();

            int count = 0;
            WatcherEngine.ProgressDialog.MaximumRange = sessions.Length;
            WatcherEngine.ProgressDialog.MinimumRange = 0;
            WatcherEngine.ProgressDialog.Increment = 1;

            foreach (Fiddler.Session s in sessions)
            {
                count++;

                WatcherEngine.ProgressDialog.labelOperation.Text = "Processing Session ID: " + s.id;
                WatcherEngine.ProgressDialog.ProgressValue = WatcherEngine.ProgressDialog.Increment;
                WatcherEngine.ProgressDialog.UpdateProgress();

                // Turn off streaming
                // TODO: this may already be the case by the time this method is called...
                s.bBufferResponse = true;

                // Remove chunking and compression from the HTTP response
                // Logging the return value may result in excessive verbosity: avoid it.
                s.utilDecodeResponse();

                // Add the specified session to the list of tracked sessions
                // Do not store session responses greater than 200k
                if (s.responseBodyBytes != null && s.responseBodyBytes.Length <= WatcherEngine.MaximumResponseLength)
                {
                    WatcherEngine.Sessions.Add(s);
                }
                else
                {
                    Trace.TraceWarning("Warning: Session ID {0} response body is null or exceeds maximum length; not storing in the session list.", s.id);
                }

                // Run the enabled Watcher checks against the session
                WatcherEngine.CheckManager.RunEnabledChecks(s);
            }
        }
    }
}