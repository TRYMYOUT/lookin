// WATCHER
//
// WatcherOffline.cs
// 
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
    /// This class implements the Watcher offline processing
    /// 
    /// 
    /// </summary>
    public sealed class WatcherOffline
    {
        #region Ctor(s)

        /// <remarks>
        /// Default public constructors should always be defined.
        /// </remarks>
        public WatcherOffline()
        {
        }

        #endregion


        /// <summary>
        /// Get all of the sessions in the session list and process them through Watcher's check engine
        /// one at a time.  Useful for processing sessions stored in a .SAZ file or otherwise when offline.
        /// </summary>
        public void ProcessSessions()
        {
            Fiddler.Session[] sessions = Fiddler.FiddlerApplication.UI.GetAllSessions();

            // count the session we're currently on, not the session.id
            int counter = 0;

            // Reset the bar's progress position
            WatcherEngine.ProgressDialog.ProgressValue = 0;
            WatcherEngine.ProgressDialog.MaximumRange = sessions.Length;
            WatcherEngine.ProgressDialog.MinimumRange = 0;
            WatcherEngine.ProgressDialog.Increment = 1;
            WatcherEngine.ProgressDialog.Title = "Offline Session Analysis";
            WatcherEngine.ProgressDialog.BodyText = "Processing session data:";


            foreach (Fiddler.Session s in sessions)
            {
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

                WatcherEngine.ProgressDialog.labelOperation.Text = String.Format("Session ID: {0} of {1}", counter, sessions.Length);
                WatcherEngine.ProgressDialog.UpdateProgress();
                // Update the counter
                counter++;
            }
        }
    }
}