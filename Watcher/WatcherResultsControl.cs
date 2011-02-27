// WATCHER
//
// WatcherResultsControl.cs
// Main implementation of Watcher Results processing.
//
// Copyright (c) 2010 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.IO;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Configuration;
using System.Diagnostics;
using System.Drawing;
using System.Net;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;
using System.Xml;
using Fiddler;
using CasabaSecurity.Web.Watcher.Collections;

namespace CasabaSecurity.Web.Watcher
{
    // TODO: Make this internal.  Checks should use ResultsManager.
    public partial class WatcherResultsControl : UserControl
    {
        #region Fields
        public WatcherResultSeverity noisereduction;
        private int highcount;
        private int mediumcount;
        private int lowcount;
        private int informationalcount;
        private int highissues;
        private int mediumissues;
        private int lowissues;
        private int informationalissues;
        private int total;
        private bool autoscroll;
        private List<ListViewItem> alerts = new List<ListViewItem>();
        private AlertListViewColumnSorter alvwColumnSorter;
        #endregion

        #region Ctor(s)
        public WatcherResultsControl()
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
                //Initialize Save Method
                //String savetoXML = "XML File";
                //this.cbExportMethod.Items.Add(savetoXML);
                
                foreach (WatcherOutputPlugin plugin in WatcherEngine.OutputPluginManager.OutputPlugins)
                {
                    this.cbExportMethod.Items.Add(plugin);
                }

                String SaveMethod = WatcherEngine.Configuration.Get("DefaultSaveMethod");
                
                if (!String.IsNullOrEmpty(SaveMethod))
                {
                    SaveMethod = Utility.Base64Decode(SaveMethod);
                    //Store with Base64 since plugins may use dangerous characters
                    for (int i = 0; i < cbExportMethod.Items.Count; i++)
                    {
                        WatcherOutputPlugin OutPlugin = (WatcherOutputPlugin)this.cbExportMethod.Items[i];
                        if (SaveMethod == OutPlugin.GetName())
                        {
                            this.cbExportMethod.SelectedItem = this.cbExportMethod.Items[i];
                            break;
                        }
                    }
                }

                // Reduce flicker
                ListViewHelper.EnableDoubleBuffer(this.alertListView);

                // Instantiate the list view comparison class
                alvwColumnSorter = new AlertListViewColumnSorter();
                this.alertListView.ListViewItemSorter = alvwColumnSorter;

                // Set the default filter level for check alerts
                this.noisereduction = WatcherResultSeverity.Informational;
                
                // TODO: Use custom Watcher configuration section
                // Use the filter level from the configuration, if it exists
                if (!String.IsNullOrEmpty(WatcherEngine.Configuration.Get("DefaultFilter")))
                {
                    this.noisereductioncomboBox.SelectedItem = WatcherEngine.Configuration.Get("DefaultFilter");
                }
                else
                {
                    //Update the Selected Item since the configuration item did not exist.
                    this.noisereductioncomboBox.SelectedItem = "Informational";
                }

                // Determine whether to auto-scroll alerts
                if (!String.IsNullOrEmpty(WatcherEngine.Configuration.Get("AutoScroll")))
                {
                    string temp = WatcherEngine.Configuration.Get("AutoScroll");
                    this.autoscrollcheckBox.Checked = Boolean.Parse(temp);
                }
                int index = this.label3.Text.IndexOf(",");
                Version currentver = new UpdateManager().CurrentVersionEngine;
                this.label3.Text = this.label3.Text.Insert(index, " v" + currentver.ToString());
            }

            textBoxSearchResults.TextChanged += new EventHandler(textBoxSearchResults_TextChanged);

 	        base.OnLoad(e);
        }

        #endregion

        #region Private Callback(s)

        /// <summary>
        /// This delegate is used to perform the export asynchronously.
        /// </summary>
        private delegate void ExportResultsCallback(WatcherOutputPlugin plugin, WatcherResultCollection resultslist, String filename);

        #endregion

        #region Public Method(s)

        /// <summary>
        /// This method adds a check result to the list view.
        /// </summary>
        /// <param name="resultSeverity">The severity of the finding.</param>
        /// <param name="sessionId">The ID of the Fiddler Session where the finding was discovered.</param>
        /// <param name="sessionUrl">The URL where the finding was discovered.</param>
        /// <param name="checkName">The name of the check that performed the analysis.</param>
        /// <param name="resultDescription">The description of the finding.</param>
        /// <param name="compliesWith">Standards implemented by Watcher that this check conforms to.</param>
        /// <param name="count">The number of times the finding was discovered.</param>
        public void AddAlert(WatcherResultSeverity resultSeverity, int sessionId, String sessionUrl, String checkName, String resultDescription, WatcherCheckStandardsCompliance compliesWith, int count, String reflink)
        {
            AlertListViewItem alvi = null;

            int highincrement = 0;
            int mediumincrement = 0;
            int lowincrement = 0;
            int informationalincrement = 0;
            int highissueincrement = 0;
            int mediumissueincrement = 0;
            int lowissueincrement = 0;
            int informationalissueincrement = 0;

            switch (resultSeverity)
            {
                case WatcherResultSeverity.High:
                    alvi = new AlertListViewItem(resultSeverity, sessionId, checkName, sessionUrl, resultDescription, count, reflink);
                    alvi.ForeColor = Color.Red;
                    highissueincrement = count;
                    highincrement++;
                    break;

                case WatcherResultSeverity.Medium:
                    alvi = new AlertListViewItem(resultSeverity, sessionId, checkName, sessionUrl, resultDescription, count, reflink);
                    alvi.ForeColor = Color.Orange;
                    mediumissueincrement = count;
                    mediumincrement++;
                    break;

                case WatcherResultSeverity.Low:
                    alvi = new AlertListViewItem(resultSeverity, sessionId, checkName, sessionUrl, resultDescription, count, reflink);
                    alvi.ForeColor = Color.Blue;
                    lowissueincrement = count;
                    lowincrement++;
                    break;

                case WatcherResultSeverity.Informational:
                    alvi = new AlertListViewItem(resultSeverity, sessionId, checkName, sessionUrl, resultDescription, count, reflink);
                    alvi.ForeColor = Color.Green;
                    informationalissueincrement = count;
                    informationalincrement++;
                    break;

                default:
                    Debug.Assert(false, "Alert severity not specified.");
                    break;
            }

            // Remove dupes
            // Testing if this is necessary
            for (int x = 0; x < this.alertListView.Items.Count; ++x)
            {
                AlertListViewItem tlvi = (AlertListViewItem)this.alertListView.Items[x];

                if (tlvi != null)
                {
                    if (tlvi.Equals(alvi))
                    {
                        return;
                    }
                }
            }

            // Update count after dealing with duplicates
            highcount = highcount + highincrement;
            mediumcount = mediumcount + mediumincrement;
            lowcount = lowcount + lowincrement;
            informationalcount = informationalcount + informationalincrement;
            highissues = highissues + highissueincrement;
            mediumissues = mediumissues + mediumissueincrement;
            lowissues = lowissues + lowissueincrement;
            informationalissues = informationalissues + informationalissueincrement;
            total = total + informationalincrement + lowincrement + mediumincrement + highincrement;

            RenderCount();
            
            alvi.SubItems.Add(sessionId.ToString());
            alvi.SubItems.Add(checkName);
            alvi.SubItems.Add(sessionUrl);

            alerts.Add(alvi);

            if (this.noisereduction <= resultSeverity)
            {
                this.alertListView.BeginUpdate();
                this.alertListView.Items.Add(alvi);
                if (autoscroll)
                {
                    this.alertListView.EnsureVisible(alertListView.Items.Count - 1);
                }
                this.alertListView.AutoResizeColumns(ColumnHeaderAutoResizeStyle.HeaderSize);
                this.alertListView.EndUpdate();
            }
        }

        #endregion

        #region Private Method(s)

        private void alertListView_ColumnClick(object o, ColumnClickEventArgs e)
        {
            alvwColumnSorter.Severity = false;

            if (e.Column == 1)
            {
                alvwColumnSorter.Number = true;
                alvwColumnSorter.Severity = false;
            }
            else
            {
                alvwColumnSorter.Number = false;
                if (e.Column == 0)
                {
                    alvwColumnSorter.Severity = true;
                }
            }

            if (e.Column == alvwColumnSorter.SortColumn)
            {
                // Reverse the current sort direction for this column.
                if (alvwColumnSorter.Order == SortOrder.Ascending)
                {
                    alvwColumnSorter.Order = SortOrder.Descending;
                }
                else
                {
                    alvwColumnSorter.Order = SortOrder.Ascending;
                }
            }
            else
            {
                // Set the column number that is to be sorted; default to ascending.
                alvwColumnSorter.SortColumn = e.Column;
                alvwColumnSorter.Order = SortOrder.Ascending;
            }

            // Perform the sort with these new sort options.
            this.alertListView.Sort();
        }

        /// <summary>
        /// This event handler method is called when the Clear Results button is clicked.
        /// 
        /// TODO:  When no selectedResults are selected by the user, this will call the check.Clear() method
        /// on each check - see the foreach loop in the 'if' block.
        /// In the 'else' block, we would have to figure out which checks' selectedResults are being cleared,
        /// then call check.Clear() on those checks specifically.
        /// 
        /// </summary>
        private void btnClearResults_Click(object sender, EventArgs e)
        {
            int count = 0;

            this.alertListView.BeginUpdate();
            if (this.alertListView.SelectedItems.Count == 0)
            {
                this.alertListView.Items.Clear();
                this.alertTextBox.Clear();
                this.alerts.Clear();
                highcount = 0;
                mediumcount = 0;
                lowcount = 0;
                informationalcount = 0;
                highissues = 0;
                mediumissues = 0;
                lowissues = 0;
                informationalissues = 0;
                // Some of the noisy checks keep lists to reduce output,
                // we need to clear their lists when the user clears the 
                // selectedResults window.
                foreach (WatcherCheck check in WatcherEngine.CheckManager.Checks)
                {
                    check.Clear();
                }
            }
            else
            {
                foreach (AlertListViewItem item in this.alertListView.SelectedItems)
                {
                    count = item.AlertCount;

                    switch (item.Severity)
                    {
                        case WatcherResultSeverity.High:
                            highcount--;
                            highissues = highissues - count;
                            break;

                        case WatcherResultSeverity.Medium:
                            mediumcount--;
                            mediumissues = mediumissues - count;
                            break;

                        case WatcherResultSeverity.Low:
                            lowcount--;
                            lowissues = lowissues - count;
                            break;

                        case WatcherResultSeverity.Informational:
                            informationalcount--;
                            informationalissues = informationalissues - count;
                            break;

                        default:
                            Debug.Assert(false, "Could not determine selected item's severity.");
                            break;
                    }

                    this.alertListView.Items.Remove(item);
                    this.alerts.Remove(item);
                    this.alertTextBox.Clear();
                }
            }

            RenderCount();
            this.alertListView.EndUpdate();
        }

        private void RenderCount()
        {
            this.highcountlabel.Text = "High: " + highcount.ToString() + " , " + highissues.ToString();
            this.mediumcountlabel.Text = "Medium: " + mediumcount.ToString() + " , " + mediumissues.ToString();
            this.lowcountlabel.Text = "Low: " + lowcount.ToString() + " , " + lowissues.ToString();
            this.informationalcountlabel.Text = "Informational: " + informationalcount.ToString() + " , " + informationalissues.ToString();
        }

        private void copyToClipboard(object sender, KeyEventArgs e)
        {
            string output = "";

            if (e.Control == true & e.KeyCode == Keys.C) 
            {
                e.Handled = true;

                foreach (AlertListViewItem item in this.alertListView.SelectedItems)
                {
                    output = output + item.ToString();
                }

                if (output != null)
                {
                    IDataObject data = new DataObject(DataFormats.StringFormat, output);
                    Clipboard.SetDataObject(data);
                }
            }
        }

        private void resultcopyToClipboard(object sender, KeyEventArgs e)
        {
            string output = "";

            if (e.Control == true & e.KeyCode == Keys.C)
            {
                e.Handled = true;
                output =  alertTextBox.SelectedText;
                if (output != null)
                {
                    IDataObject data = new DataObject(DataFormats.StringFormat, output);
                    Clipboard.SetDataObject(data);
                }
            }
        }

        /// <summary>
        /// This event handler method is called when an item in the Alert List View is double-clicked.
        /// </summary>
        private void alertListViewDoubleClick(object o, EventArgs e)
        {
            try
            {
                // Session ID as Fiddler marked it
                int sessionId = ((AlertListViewItem)this.alertListView.SelectedItems[0]).ID;

                // Index of the Session ID in the Fiddler list
                int index = 0;

                // Clear any selected session in the session list
                FiddlerApplication.UI.lvSessions.SelectedItems.Clear();

                Session[] sessionArray = FiddlerApplication.UI.GetAllSessions();
                for (int i = 0; i < sessionArray.Length; i++)
                {
                    if (sessionArray[i].id == sessionId)
                    {
                        index = i;
                        break;
                    }
                }

                FiddlerApplication.UI.lvSessions.Items[index].Focused = true;
                FiddlerApplication.UI.lvSessions.Items[index].Selected = true;
                // Active the Raw request/response inspector for this session
                FiddlerApplication.UI.actInspectSession();
                FiddlerApplication.UI.ActivateRequestInspector("Raw");
                FiddlerApplication.UI.ActivateResponseInspector("Raw");
            }

            catch (ArgumentOutOfRangeException)
            {
                MessageBox.Show("Session not found in Fiddler's list - was it removed?");
            }

            base.OnDoubleClick(e);
        }

        /// <summary>
        /// This event handler method is called when the user selects an item from the selectedResults list.
        /// </summary>
        private void alertListView_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (this.alertListView.SelectedItems.Count == 1)
            {
                this.alertTextBox.Text = ((AlertListViewItem)this.alertListView.SelectedItems[0]).Description;
                this.reflinkLabel.Text = ((AlertListViewItem)this.alertListView.SelectedItems[0]).refLink;
            }
        } 

        /// <summary>
        /// This is an event handler called when the user clicks the Export button.
        /// </summary>
        private void FileSaveButton_Click(object sender, EventArgs e)
        {
            
            // If no export method is selected, bail.
            if (cbExportMethod.SelectedItem == null)
            {
                MessageBox.Show("No export method selected.  Please select an export method.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            // Gather the selected results
            WatcherResultCollection selectedResults = new WatcherResultCollection();
            
            foreach (AlertListViewItem item in alertListView.Items)
            {
                WatcherResult result = new WatcherResult();
                result.Description = item.Description;
                result.Severity = item.Severity;
                result.Title = item.TypeX;
                result.URL = item.URL;

                selectedResults.Add(result);
            }

            // The export method refers to an instance of the output plugin
            WatcherOutputPlugin outputPlugin = cbExportMethod.SelectedItem as WatcherOutputPlugin;
            if (outputPlugin == null)
            {
                Trace.TraceError("WatcherResultsControl: Invalid export method selected.");
                MessageBox.Show("Unable to use the selected export method.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            String filename = String.Empty;
            String filter = String.Empty;

            // If this plugin is a file-based export, open a file save dialog and allow
            // the user to select the output filename.  Use the default values provided
            // by the plugin.
            //
            // TODO: Plugin should be interface-based or provide a property to tell whether it is a file-based export or not
            if (outputPlugin.GetExportDefaults(ref filename, ref filter))
            {
                SaveFileDialog dlg = new SaveFileDialog();
                dlg.FileName = filename;
                dlg.Filter = filter;
                dlg.InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                dlg.FilterIndex = 1;
                dlg.RestoreDirectory = true;

                // Display the dialog, and if canceled, abort.
                if (dlg.ShowDialog() != DialogResult.OK)
                {
                    Trace.TraceInformation("User canceled export.");
                    return;
                }

                // Update the filename selected by the user
                filename = dlg.FileName;
            }

            // This is the export progress dialog shown during the export process

            // CHANGE - potentially breaking change, removing progress dialog
            // which seems to be dreadfully slowing down real work.
            WatcherEngine.ProgressDialog.Show();
            WatcherEngine.ProgressDialog.Title = "Export Data";

            // Perform the export asynchronously
            ExportResultsCallback callback = new ExportResultsCallback(ExportResults);
            callback.BeginInvoke(outputPlugin, selectedResults, filename,

                // This is the anonymous callback method
                delegate(IAsyncResult ar)
                {
                    try
                    {
                        // Tidy up after the export
                        ExportResultsCallback _callback = (ExportResultsCallback)ar.AsyncState;
                        _callback.EndInvoke(ar); // NOTE: This will throw any unhandled exceptions that happened during the call
                    }

                    catch (WatcherException ex)
                    {
                        Trace.TraceError("Exception: {0}", ex.Message);
                        if (ex.Data.Contains("UserAbortedOperation") == false)
                        {
                            // Only show a message box if the user hasn't already seen one (i.e., they've elected to abort the operation)
                            MessageBox.Show(this, String.Format("{0}", ex.Message), "Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        }
                        return;
                    }

                    finally
                    {
                        // CHANGE - see above breaking change, removing progress dialog.
                        WatcherEngine.ProgressDialog.Hide();
                    }

                    MessageBox.Show(this, "Items successfully exported.", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
                },

            // Pass the callback as user data so we can call EndInvoke() when the operation completes
            // to retrieve the result.
            callback);
        }

        /// <summary>
        /// This method is the delegate called when an export is to be handled using a plugin.
        /// </summary>
        /// <returns>True if the operation succeeded, False otherwise.</returns>
        private void ExportResults(WatcherOutputPlugin plugin, WatcherResultCollection results, String filename)
        {
            // Perform the Save operation.  Not every save operation will return a
            // stream; therefore, a null return value is not necessarily an error.
            //
            // TODO: This class is a candidate for redesign as it handles exports with different semantics (e.g., TFS)
            Stream outputStream = plugin.SaveResult(results);
            if (outputStream != null)
            {
                using (FileStream fs = new FileStream(filename, FileMode.Create))
                {
                    Utility.ReadWriteStream(outputStream, fs);
                }
            }
        }

        /// <summary>
        /// This event handler method is called when the Alert Filter combobox is changed.
        /// </summary>
        private void comboBox1_SelectedIndexChanged(object sender, EventArgs e)
        {
            string selection = this.noisereductioncomboBox.SelectedItem.ToString();

            if (selection == WatcherResultSeverity.Informational.ToString())
            {
                this.noisereduction = WatcherResultSeverity.Informational;
            }
            else if (selection == WatcherResultSeverity.Low.ToString())
            {
                this.noisereduction = WatcherResultSeverity.Low;
            }
            else if (selection == WatcherResultSeverity.Medium.ToString())
            {
                this.noisereduction = WatcherResultSeverity.Medium;
            }
            else if (selection == WatcherResultSeverity.High.ToString())
            {
                this.noisereduction = WatcherResultSeverity.High;
            }

            this.alertListView.BeginUpdate();
            foreach (ListViewItem item in this.alertListView.Items)
            {
                this.alertListView.Items.Remove(item);
                this.alertTextBox.Clear();
            }

            foreach (AlertListViewItem item in alerts)
            {
                if (item.Severity >= this.noisereduction)
                {
                    this.alertListView.Items.Add(item);
                }
            }
            this.alertListView.AutoResizeColumns(ColumnHeaderAutoResizeStyle.HeaderSize);
            this.alertListView.EndUpdate();

            WatcherEngine.Configuration.Remove("DefaultFilter");
            WatcherEngine.Configuration.Add("DefaultFilter", this.noisereductioncomboBox.SelectedItem.ToString());      
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
                System.Diagnostics.Process.Start("http://www.casaba.com/");
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

        /// <summary>
        /// This event handler method is called when the High alert count label is clicked.
        /// </summary>
        private void highcountlabel_Click(object sender, EventArgs e)
        {
            this.noisereductioncomboBox.SelectedItem = "High";
        }

        /// <summary>
        /// This event handler method is called when the Medium alert count label is clicked.
        /// </summary>
        private void mediumcountlabel_Click(object sender, EventArgs e)
        {
            this.noisereductioncomboBox.SelectedItem = "Medium";
        }

        /// <summary>
        /// This event handler method is called when the Low alert count label is clicked.
        /// </summary>
        private void lowcountlabel_Click(object sender, EventArgs e)
        {
            this.noisereductioncomboBox.SelectedItem = "Low";
        }

        /// <summary>
        /// This event handler method is called when the Informational count label is clicked.
        /// </summary>
        private void informationalcountlabel_Click(object sender, EventArgs e)
        {
            this.noisereductioncomboBox.SelectedItem = "Informational";
        }

        /// <summary>
        /// This event handler method is called when the AutoScroll checkbox is clicked.
        /// </summary>
        private void autoscrollcheckBox_CheckedChanged(object sender, EventArgs e)
        {
            WatcherEngine.Configuration.Remove("AutoScroll");
            WatcherEngine.Configuration.Add("AutoScroll", this.autoscrollcheckBox.Checked.ToString());
            autoscroll = this.autoscrollcheckBox.Checked;
        } 

        private void savemethodcomboBox_SelectedIndexChanged(object sender, EventArgs e)
        {
            WatcherEngine.Configuration.Remove("DefaultSaveMethod");
            WatcherEngine.Configuration.Add("DefaultSaveMethod", Utility.Base64Encode(this.cbExportMethod.SelectedItem.ToString()));
        }

        private void reflinkLabel_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            try
            {
                e.Link.Visited = true;
                System.Diagnostics.Process.Start(reflinkLabel.Text);
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

        #endregion

        private void textBoxSearchResults_TextChanged(object sender, EventArgs e)
        {

            string search = textBoxSearchResults.Text;

            this.alertListView.BeginUpdate();
            foreach (ListViewItem item in this.alertListView.Items)
            {
                this.alertListView.Items.Remove(item);
                this.alertTextBox.Clear();
            }

            foreach (AlertListViewItem item in alerts)
            {
                if(item.TypeX.Contains(search) || item.Description.Contains(search))
                {
                    this.alertListView.Items.Add(item);
                }
            }
            this.alertListView.AutoResizeColumns(ColumnHeaderAutoResizeStyle.HeaderSize);
            alertListView.EndUpdate();
        }

        private void filterpanel_Paint(object sender, PaintEventArgs e)
        {

        }
    }
}