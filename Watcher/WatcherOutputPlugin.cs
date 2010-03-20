// WATCHER
//
// WatcherCheck.cs
// Main implementation of WatcherCheck Class.
//
// Copyright (c) 2010 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.IO;
using System.Reflection;
using System.Web;
using System.Collections.Specialized;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using Fiddler;
using CasabaSecurity.Web.Watcher.Collections;

namespace CasabaSecurity.Web.Watcher
{
    public abstract class WatcherOutputPlugin
    {
        #region Fields

        #endregion

        #region Ctor(s)

        // TODO: POTENTIALLY BREAKING CHANGE: public -> protected
        protected WatcherOutputPlugin()
        {
        }

        #endregion

        #region Public Properties

        #endregion

        #region Public Methods

        public virtual String GetName()
        {
            return base.ToString();
        }

        public virtual bool GetExportDefaults(ref String defaultFilename, ref String defaultFilter)
        {
            return false;
        }

        public virtual String GetDescription()
        {
            return base.ToString();
        }

        public virtual System.Windows.Forms.Panel GetConfigPanel()
        {
            return new System.Windows.Forms.Panel();
        }

        //Standard Compliance Handling?
        /// <summary>
        /// This method Takes a single result and processes for output.
        /// </summary>
        public abstract Stream SaveResult(WatcherResultCollection result);

        public override string ToString()
        {
            return GetName();
        }

        #endregion

        #region Private Method(s)

        #endregion
    }
}