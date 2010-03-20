// WATCHER
//
// OutputPluginManager.cs
// Implements types responsible for managing discovery and invocation of Watcher Output Plugins.
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
    /// This class is responsible for managing discovery and invocation of Watcher OuputPlugins.
    /// </summary>
    internal class OutputPluginManager
    {
        #region Fields
        private Object _lock = new Object();            // Use this object to provide synchronization
        private WatcherOutputPluginCollection _plugins; // Master list of plugins
        #endregion

        #region Ctor(s)
        /// <remarks>
        /// Default public constructors should always be defined.
        /// </remarks>
        public OutputPluginManager()
        {
        }
        #endregion

        #region Public Properties

        /// <summary>
        /// Returns any error message resulting from loading the plugins.
        /// </summary>
        public String ErrorMessage
        {
            get { return _plugins == null ? String.Empty : _plugins.ErrorMessage; }
        }

        /// <summary>
        /// Return a list of the checks available for use.
        /// </summary>
        public WatcherOutputPluginCollection OutputPlugins
        {
            get
            {
                if (_plugins == null)
                {
                    lock (_lock)
                    {
                        if (_plugins == null)
                        {
                            _plugins = new WatcherOutputPluginCollection();
                            _plugins.Load();
                        }
                    }
                }
                return _plugins;
            }
        }

        #endregion

        #region Private Method(s)

        #endregion

        #region Public Method(s)

        #endregion
    }
}
