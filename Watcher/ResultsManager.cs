// WATCHER
//
// ResultsManager.cs
// Implements types responsible for managing check selectedResults and analysis information.
//
// Copyright (c) 2010 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Data;
using System.Collections.Generic;
using System.Text;

namespace CasabaSecurity.Web.Watcher
{
    /// <summary>
    /// This class is responsible for handling check result/analysis information.
    /// </summary>
    /// <remarks>TODO: This can probably be broken out into a separate SDK.</remarks>
    public sealed class ResultsManager
    {
        #region Ctor(s)
        public ResultsManager()
        {
        }
        #endregion

        #region Public Method(s)

        /// <summary>
        /// This method adds a result from a check to the UI result control.
        /// </summary>
        /// <param name="resultSeverity">The severity of the finding.</param>
        /// <param name="sessionId">The ID of the Fiddler Session where the finding was discovered.</param>
        /// <param name="sessionUrl">The URL where the finding was discovered.</param>
        /// <param name="checkName">The name of the check that performed the analysis.</param>
        /// <param name="resultDescription">The description of the finding.</param>
        /// <param name="compliesWith">Standards implemented by Watcher that this check conforms to.</param>
        /// <param name="count">The number of times the finding was discovered.</param>
        public void Add(WatcherResultSeverity resultSeverity, Int32 sessionId, String sessionUrl, String checkName, String resultDescription, WatcherCheckStandardsCompliance compliesWith, Int32 count, String refLink)
        {
            
            // Add a result record to the database
            Result result = new Result(resultSeverity,sessionId,checkName,sessionUrl,resultDescription,count, compliesWith, refLink);
            int resultId = ResultsData.AddResult(result);
            DataRow row = null;
            // Don't add results unless they were unique
            if (resultId != -1)
            {
                // Get the Row data that was added
                row = ResultsData.GetResultDataRow(resultId);
                // Push the row to the TreeView
                
                // Call AddAlert with callback and pass the DataRow in there.  Change the AddAlert parameters to only take this one object.

            }

            // TODO: ResultsData.cs Update: The AddAlert calls below should be changed to use the data from the data table.

            WatcherResultsControl control = WatcherEngine.UI.WatcherResultsControl;
            
            // A control cannot be updated from a non-UI thread.  If the InvokeRequired property is set,
            // we are on a non-UI thread and must post a message to the UI thread to handle the update on
            // our behalf.  According to Richter, this is one of the few instances where BeginInvoke can
            // be called without a corresponding EndInvoke().
            if (control.InvokeRequired)
            {
                // We're not the UI thread: marshall an update to the control asynchronously
                control.BeginInvoke(new AddAlertCallback(control.AddAlert), new Object[] { resultSeverity, sessionId, sessionUrl, checkName, resultDescription, compliesWith, count, refLink, row });
                
                // control.BeginInvoke(new AddResultCallback(control.AddResultToTreeView), result);
            }
            else
            {
                // We're the UI thread, update the control directly
                control.AddAlert(resultSeverity, sessionId, sessionUrl, checkName, resultDescription, compliesWith, count, refLink, row);
                //control.AddResultToTreeView(result);
            }
        }

        /// <summary>
        /// This method adds a single result from a check to the UI result control.
        /// </summary>
        /// <param name="resultSeverity">The severity of the finding.</param>
        /// <param name="sessionId">The ID of the Fiddler Session where the finding was discovered.</param>
        /// <param name="sessionUrl">The URL where the finding was discovered.</param>
        /// <param name="checkName">The name of the check that performed the analysis.</param>
        /// <param name="resultDescription">The description of the finding.</param>
        /// <param name="compliesWith">Standards implemented by Watcher that this check conforms to.</param>
        public void Add(WatcherResultSeverity resultSeverity, Int32 sessionId, String sessionUrl, String checkName, String resultDescription, WatcherCheckStandardsCompliance compliesWith)
        {
            Add(resultSeverity, sessionId, sessionUrl, checkName, resultDescription, compliesWith, 1, String.Empty);
        }

        /// <summary>
        /// TODO: fixup documentation for this function.
        /// </summary>
        /// <param name="resultSeverity"></param>
        /// <param name="sessionId"></param>
        /// <param name="sessionUrl"></param>
        /// <param name="checkName"></param>
        /// <param name="resultDescription"></param>
        /// <param name="compliesWith"></param>
        /// <param name="num"></param>
        public void Add(WatcherResultSeverity resultSeverity, Int32 sessionId, String sessionUrl, String checkName, String resultDescription, WatcherCheckStandardsCompliance compliesWith, Int32 num)
        {
            Add(resultSeverity, sessionId, sessionUrl, checkName, resultDescription, compliesWith, num, String.Empty);
        }

        #endregion

        #region Delegate(s)

        /// <summary>
        /// This callback is used to update UI controls from a non-UI thread.
        /// </summary>
        private delegate void AddAlertCallback(WatcherResultSeverity resultSeverity, Int32 sessionId, String sessionUrl, String checkName, String checkDescription, WatcherCheckStandardsCompliance compliesWith, Int32 count, String refLink, DataRow row);
        // TODO: Get rid of AddAlertCallback in place of AddResultCallback
        //private delegate void AddResultCallback(Result result);

        #endregion
    }
}
