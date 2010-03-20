// WATCHER
//
// FiddlerWatcherExtension.cs
// This class implements the entry point for Watcher.
//
// Copyright (c) 2010 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.IO;
using System.Collections;
using System.Collections.Specialized;
using System.Collections.Generic;
using System.Diagnostics;
using System.Xml;
using System.Drawing;
using System.Net;
using System.Windows.Forms;
using System.Threading;
using System.Text;
using System.Text.RegularExpressions;
using System.Resources;
using System.Globalization;
using Fiddler;

namespace CasabaSecurity.Web.Watcher
{
    /// <summary>
    /// This class implements the Watcher Security Auditor extension.
    /// </summary>
    public class FiddlerWatcherExtension : Fiddler.IAutoTamper
    {
        #region Ctor(s)
        public FiddlerWatcherExtension()
        {
        }
        #endregion

        #region IAutoTamper Members

        /// <summary>
        /// This method is called after the user has had the chance to edit the request using the Fiddler Inspectors, but before the request is sent.
        /// </summary>
        void IAutoTamper.AutoTamperRequestAfter(Session oSession)
        {
        }

        /// <summary>
        /// This method is called before the user can edit a request using the Fiddler Inspectors.
        /// </summary>
        void IAutoTamper.AutoTamperRequestBefore(Session oSession)
        {
        }

        /// <summary>
        /// This method is called after the user edited a response using the Fiddler Inspectors.  Not called when streaming.
        /// </summary>
        void IAutoTamper.AutoTamperResponseAfter(Session oSession)
        {
        }

        /// <summary>
        /// This method is called before the user can edit a response using the Fiddler Inspectors, unless streaming.
        /// In Watcher, it is responsible for running checks against the response.
        /// </summary>
        /// <remarks>This method can be called before OnLoad() had finished initalizing! TODO: WatcherEngine.IsLoaded</remarks>
        void IAutoTamper.AutoTamperResponseBefore(Session oSession)
        {
            // Make sure the Watcher is initialized and enabled before processing the session
            if (WatcherEngine.Initialized == false || WatcherEngine.Configuration.Enabled == false)
            {
                return;
            }

            // Turn off streaming
            // TODO: this may already be the case by the time this method is called; it may want to be set in AutoTamperRequestBefore/After
            oSession.bBufferResponse = true;
            
            // Remove chunking and compression from the HTTP response
            // Logging the return value may result in excessive verbosity: avoid it.
            oSession.utilDecodeResponse();

            // Add the specified session to the list of tracked sessions
            // Do not store session responses greater than 200k
            if (oSession.responseBodyBytes != null && oSession.responseBodyBytes.Length <= WatcherEngine.MaximumResponseLength)
            {
                WatcherEngine.Sessions.Add(oSession);
            }
            else
            {
                Trace.TraceWarning("Warning: Session ID {0} response body is null or exceeds maximum length; not storing in the session list.", oSession.id);
            }

            // Run the enabled Watcher checks against the session
            WatcherEngine.CheckManager.RunEnabledChecks(oSession);
        }

        /// <summary>
        /// This method is called Fiddler returns a self-generated HTTP error (for instance DNS lookup failed, etc)
        /// </summary>
        void IAutoTamper.OnBeforeReturningError(Session oSession)
        {
        }

        #endregion

        #region IFiddlerExtension Members

        /// <summary>
        /// This method is called when Fiddler is shutting down.
        /// </summary>
        void IFiddlerExtension.OnBeforeUnload()
        {
        }

        /// <summary>
        /// This method is called when Fiddler User Interface is fully available.
        /// </summary>
        void IFiddlerExtension.OnLoad()
        {
            WatcherEngine.Init();
        }

        #endregion
    }
}
