// WATCHER
//
// WatcherEngine.cs
// Implements a fascade for Watcher operations management.
//
// Copyright (c) 2009 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Text;
using System.Windows.Forms;

using Fiddler;
using CasabaSecurity.Web.Watcher.Collections;

namespace CasabaSecurity.Web.Watcher
{
    // TODO: All static?
    // TODO: Comment: Fascade
    public sealed class WatcherEngine
    {
        #region Public Fields
        public const int MaximumResponseLength = 200 * 1024;                                    // Maximum response size is 200KB
        #endregion

        #region Private fields
        private static Object _lock = new Object();                                             // Use this object to provide synchronization
        private static CheckManager _CheckManager = new CheckManager();                         // Instance of the Watcher Check Manager
        private static WatcherConfiguration _Configuration = new WatcherConfiguration();        // Instance of the Watcher Configuration Manager
        private static ResultsManager _Results = new ResultsManager();                          // Instance of the Watcher Results Manager
        private static FiddlerSessionCollection _Sessions = new FiddlerSessionCollection();     // Keep a fixed list of sessions so checks can reference a referrer or past session if needed.
        private static WatcherControl _WatcherControl = null;                                   // The Casaba Security Auditor tab in Fiddler
        private static Boolean _Initialized = false;                                            // True when the engine has been initialized (e.g. checks loaded, configuration read).
        #endregion

        #region Ctor(s)

        /// <remarks>
        /// Default public constructors should always be defined.
        /// </remarks>
        public WatcherEngine()
        {
        }

        #endregion

        #region Private Method(s)

        /// <summary>
        /// This method throws an exception if the WatcherEngine.Init() method has not yet been called.
        /// </summary>
        /// <exception cref="InvalidOperationException">Thrown if the WatcherEngine.Init() method has not yet been called.</exception>
        private static void AssertInitialized()
        {
            lock (_lock)
            {
                if (_Initialized == false)
                {
                    String errorMessage = "WatcherEngine has not yet been initialized.";
                    Trace.TraceError(String.Format("Error: {0}", errorMessage));
                    Debug.Assert(false, errorMessage);
                    throw new InvalidOperationException(errorMessage);
                }
            }
        }

        #endregion

        #region Public Properties

        /// <summary>
        /// This property returns the Watcher Check Manager.
        /// </summary>
        /// <remarks>This is internal to prevent access from the checks, which a separate SDK project may solve.</remarks>
        /// TODO: CheckManager->WatcherCheckManager
        internal static CheckManager CheckManager
        {
            get 
            {
                AssertInitialized();
                return _CheckManager; 
            }
        }

        /// <summary>
        /// This property returns the Watcher Configuration Manager.
        /// </summary>
        /// TODO: WatcherConfiguration->WatcherConfigurationManager
        public static WatcherConfiguration Configuration
        {
            get 
            {
                AssertInitialized();
                return _Configuration; 
            }
        }

        /// <summary>
        /// This property indicates whether or not the engine has been initialized (and is ready for operation).
        /// </summary>
        public static Boolean Initialized
        {
            get { return _Initialized; }
        }

        /// <summary>
        /// This property returns the Watcher Results Manager.
        /// </summary>
        public static ResultsManager Results
        {
            get
            {
                AssertInitialized();
                return _Results;
            }
        }

        /// <summary>
        /// A running list of Fiddler session objects.  You may want to access these by the session.fullUrl property,
        /// but remember this property is URL encoded when you try to access it.
        /// </summary>
        /// <remarks>The collection returned is thread-safe.</remarks>
        public static FiddlerSessionCollection Sessions 
        {
            get 
            {
                AssertInitialized();
                return _Sessions; 
            }
        }

        /// <summary>
        /// This property returns a reference to the Casaba Security Auditor tab in Fiddler.
        /// </summary>
        public static WatcherControl UI
        {
            get
            {
                AssertInitialized();
                return _WatcherControl;
            }
        }

        #endregion

        #region Public Method(s)

        /// <summary>
        /// This method is called to initialize the Watcher Engine after the Fiddler UI has been loaded.
        /// </summary>
        public static void Init()
        {
            // The engine shouldn't be initialized more than once
            if (_Initialized == true)
            {
                String errorMessage = "WatcherEngine has already been initialized.";
                Trace.TraceError(String.Format("Error: {0}", errorMessage));
                Debug.Assert(false, errorMessage);
                throw new InvalidOperationException(errorMessage);
            }

            lock (_lock)
            {
                // Prevent multiple initializations if called from multiple threads (shouldn't happen)
                if (_Initialized == false)
                {
                    // Set up exception handlers for any exceptions that aren't caught conventionally
                    Application.ThreadException += new System.Threading.ThreadExceptionEventHandler(ExceptionLogger.OnThreadException);
                    AppDomain.CurrentDomain.UnhandledException += new UnhandledExceptionEventHandler(ExceptionLogger.OnUnhandledException);

                    // Load configuration before UI gets setup
                    _Configuration.Load();

                    // Instantiate and initialize the Watcher UI
                    _WatcherControl = new WatcherControl();

                    _Initialized = true;
                }
            }
        }

        #endregion
    }
}
