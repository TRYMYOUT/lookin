using System;
using System.IO;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Threading;
using System.Reflection;
using System.Windows.Forms;
using System.Collections;
using System.Collections.Specialized;
using System.Xml;
using Microsoft.TeamFoundation;
using Microsoft.TeamFoundation.Client;
using Microsoft.TeamFoundation.Common;
using Microsoft.TeamFoundation.WorkItemTracking.Client;
using CasabaSecurity.Web.Watcher;
using CasabaSecurity.Web.Watcher.Collections;

namespace CasabaSecurity.Web.Watcher.TeamFoundation
{
    public partial class TeamFoundationOutputPlugin : WatcherOutputPlugin
    {
        #region Private Member(s)
        private TeamFoundationPluginConfigPanel _configurationPanel;
        private TeamFoundationAdapter _adapter;
        #endregion

        #region Public Method(s)

        /// <summary>
        /// Initialize the Team Foundation Server output plugin.
        /// </summary>
        public TeamFoundationOutputPlugin()
        {
            _configurationPanel = new TeamFoundationPluginConfigPanel(this);
            _configurationPanel.Init();
        }

        /// <summary>
        /// This method returns the name of the output plugin.
        /// </summary>
        public override String GetName()
        {
            return "Team Foundation Server";
        }

        /// <summary>
        /// This method returns a description of the output plugin.
        /// </summary>
        public override String GetDescription()
        {
            return "This plugin supports connecting to a Team Foundation Server and adding a bug report containing a selected set Watcher results.";
        }

        /// <summary>
        /// This method returns a configuration panel for use in the Watcher configuration UI.
        /// </summary>
        /// <returns>Panel for use in the configuration.</returns>
        public override System.Windows.Forms.Panel GetConfigPanel()
        {
            System.Windows.Forms.Panel panel1 = new System.Windows.Forms.Panel();
            panel1.Controls.Add(_configurationPanel);
            panel1.AutoSize = true;
            return panel1;
        }

        /// <summary>
        /// This method saves the collection of Watcher findings to the Team Foundation Server specified in the UI.
        /// </summary>
        /// <param name="watcherResults">Collection of Watcher findings to export.</param>
        /// <returns>This method always returns null for Team Foundation Server exports.</returns>
        public override Stream SaveResult(WatcherResultCollection watcherResults)
        {
            Trace.TraceInformation("Exporting {0} items...", watcherResults.Count);

            // Create an instance of the Watcher Result to Team Foundation Work Item adapter
            _adapter = TeamFoundationAdapter.Create(_configurationPanel.servername, _configurationPanel.projectname);

            Trace.TraceInformation("Connecting to Team Foundation Server...");
            WatcherEngine.ProgressDialog.UpdateProgress("Connecting to Team Foundation Server...");

            // Attempt to connect to the Team Foundation Server specified in the configuration panel
            try { _adapter.Connect(); }
            catch (WatcherException ex)
            {
                Trace.TraceError("Unable to connect to Team Foundation Server \"{0}\": {1}", _adapter.ServerName, ex.Message);
                throw;
            }

            Trace.TraceInformation("Opening the project...");
            WatcherEngine.ProgressDialog.UpdateProgress("Opening the project...");

            // Attempt to open the Team Foundation Project specified in the configuration panel
            try { _adapter.OpenProject(); }
            catch (WatcherException ex)
            {
                Trace.TraceError("Unable to connect to Team Foundation Server \"{0}\": {1}", _adapter.ServerName, ex.Message);
                throw;
            }

            // TODO: collect results and throw with error
            // Enumerate and export the results
            for (int ndx = 0; ndx < watcherResults.Count;)
            {
                // Reset the progress bar for each finding exported
                WatcherEngine.ProgressDialog.ProgressValue = 10;

                // Determine the current finding
                WatcherResult watcherResult = watcherResults[ndx];

                // Export the current finding
                try { ExportResult(watcherResult); }
                catch (WatcherException ex)
                {
                    DialogResult dlgResult = MessageBox.Show(ex.Message, "Error", MessageBoxButtons.AbortRetryIgnore, MessageBoxIcon.Warning);
                    switch (dlgResult)
                    {
                        case DialogResult.Abort:
                            Trace.TraceInformation("User has aborted the export.");
                            WatcherException e = new WatcherException(ex.Message);
                            e.Data["UserAbortedOperation"] = true;  // Prevent an additional dialog from appearing when the exception is
                            throw e;                                // rethrown to abort the operation.

                        case DialogResult.Retry:
                            Trace.TraceInformation("User is attempting to retry the export of item \"{0}\".", watcherResult.Title);
                            continue;

                        case DialogResult.Ignore:
                            break;
                    }
                }

                // Continue with the next finding
                ++ndx;
            }

            // TODO: Make the SaveResult return type more generic.  Returning null here is
            // a kludge since output plugins were originally intended to return a Stream.
            return null;
        }

        #endregion
    }
}