﻿// WATCHER
//
// CheckManager.cs
// Implements types responsible for managing discovery and invocation of Watcher checks.
//
// Copyright (c) 2010 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security;
using System.Text;
using System.Threading;

using Fiddler;
using CasabaSecurity.Web.Watcher.Collections;

namespace CasabaSecurity.Web.Watcher
{
    /// <summary>
    /// This class is responsible for managing discovery and invocation of Watcher checks.
    /// </summary>
    internal class CheckManager
    {
        #region Nested Type(s)

        /// <summary>
        /// This type contains the state passed to every check that is executed.
        /// </summary>
        private struct WatcherCheckState
        {
            public Session session;
            public WatcherCheck check;
            public UtilityHtmlParser parser;
        }

        #endregion

        #region Fields
        private Object _lock = new Object();     // Use this object to provide synchronization
        private WatcherCheckCollection _checks;  // Master list of checks
        #endregion

        #region Ctor(s)
        /// <remarks>
        /// Default public constructors should always be defined.
        /// </remarks>
        public CheckManager()
        {
        }
        #endregion

        #region Public Properties

        /// <summary>
        /// Return a list of the checks available for use.
        /// </summary>
        public WatcherCheckCollection Checks
        {
            get 
            {
                if (_checks == null)
                {
                    lock (_lock)
                    {
                        if (_checks == null)
                        {
                            _checks = new WatcherCheckCollection();
                            _checks.Load();
                        }
                    }
                }
                return _checks; 
            }
        }

        #endregion

        #region Private Method(s)

        /// <summary>
        /// This method invokes a check on a thread from the thread pool.
        /// </summary>
        /// <param name="threadContext">State object specified by the caller to QueueUserWorkItem.</param>
        private void ThreadPoolCallback(Object threadContext)
        {
            try
            {
                // Ensure the thread state is of the correct type
                if (!(threadContext is WatcherCheckState))
                {
                    Trace.TraceError("Error: State passed to Watcher check is not of the proper type.");
                    return;
                }

                WatcherCheckState threadState = (WatcherCheckState)threadContext;

                // Invoke the check
                Debug.Print("Running check {0} on session ID {1}.", threadState.check.GetName(), threadState.session.id);
                threadState.check.Check(threadState.session, threadState.parser);
            }

            catch (Exception e)
            {
                Trace.TraceWarning("Warning: Watcher check threw an unhandled exception: {0}", e.Message);
                ExceptionLogger.HandleException(e);
            }
        }

        #endregion

        #region Public Method(s)

        /// <summary>
        /// This method invokes all enabled checks against the given session.
        /// </summary>
        /// <param name="oSession">Instance of the Fiddler session to examine.</param>
        public void RunEnabledChecks(Session oSession)
        {
            // Ignore proxy requests
            if ((oSession.oRequest.headers.HTTPMethod.Equals("CONNECT")))
            {
                Trace.TraceInformation("Ignoring proxy request on session ID {0}.", oSession.id);
                return;
            }

            Trace.TraceInformation("Running checks on session ID {0}.", oSession.id);
            lock (_lock)
            {
                WatcherCheckState state = new WatcherCheckState();
                state.session = oSession;
                state.parser = new UtilityHtmlParser(oSession);

                // Enumerate the available checks
                foreach (WatcherCheck check in Checks)
                {
                    // Skip disabled checks
                    if (check.Enabled == false)
                    {
                        Trace.TraceInformation("Skipping disabled check \"{0}\".", check.GetName());
                        continue;
                    }

                    // ... and run the enabled ones
                    state.check = check;
                    ThreadPool.QueueUserWorkItem(ThreadPoolCallback, state);
                }
            }
        }

        #endregion
    }
}