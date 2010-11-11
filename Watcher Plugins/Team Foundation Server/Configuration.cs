// Casaba Watcher Team Foundation Export Adapter Plugin
// Copyright (c) 2010 Casaba Security, LLC.  All rights reserved.

using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security;
using System.Text;
using System.Windows.Forms;
using System.Xml;
using System.Xml.Linq;
using Microsoft.TeamFoundation;
using Microsoft.TeamFoundation.Client;
using Microsoft.TeamFoundation.Common;
using Microsoft.TeamFoundation.WorkItemTracking.Client;
using CasabaSecurity.Web.Watcher.Collections;

namespace CasabaSecurity.Web.Watcher.TeamFoundation
{
    internal partial class TeamFoundationConfiguration
    {
        #region Private Member(s)

        private XDocument _configurationDocument = null;
        private List<String> _configurationErrors = new List<String>();
        private FindingsMap _findingEntry = new FindingsMap();
        private Dictionary<String, TranslationEntry> _translationDictionary = new Dictionary<String, TranslationEntry>();

        #endregion

        #region Properties

        /// <summary>
        /// This property gets error encountered during validation of the plugin configuration.
        /// </summary>
        public List<String> Errors 
        {
            get { return _configurationErrors; } 
        } 

        /// <summary>
        /// This property gets the type representing the fields to be exported to a Team Foundation Server.
        /// </summary>
        public FindingsMap ExportMap 
        {
            get { return _findingEntry; }
        }

        /// <summary>
        /// This property gets a dictionary whose key represents a Watcher field, and whose value contains
        /// a type that maps values in Watcher to values accepted by a TFS template.
        /// </summary>
        private Dictionary<String, TranslationEntry> Translation 
        {
            get { return _translationDictionary; } 
        }

        #endregion

        #region ctor/dtor(s)

        public TeamFoundationConfiguration()
        {
        }

        #endregion

        #region Public Method(s)

        /// <summary>
        /// This method loads the Team Foundation Server Export Adapter configuration.
        /// </summary>
        public void Load()
        {
            Clear();
            LoadInternal();
            Parse();
        }

        /// <summary>
        /// This method returns the value that should be used in a TFS field, given a
        /// Watcher field name and value.
        /// </summary>
        /// <param name="watcherFieldName">The Watcher field name to be translated.</param>
        /// <param name="watcherFieldValue">The Watcher value to be translated.</param>
        /// <returns>The value that should be passed to TFS for the field that maps to the Watcher field.</returns>
        public String GetTranslatedValue(String watcherFieldName, String watcherFieldValue)
        {
            // If the translation table contains an entry for the specified field name, and
            // an entry for that field's value, return the corresponding TFS field value.
            if (Translation.ContainsKey(watcherFieldName))
            {
                if (Translation[watcherFieldName].TranslationTable.ContainsKey(watcherFieldValue))
                {
                    return Translation[watcherFieldName].TranslationTable[watcherFieldValue];
                }
            }

            // XXX TODO: evaluate whether or not this is the right exception to throw
            // TODO: Sanitize fields?
            // The translation table does not contain an entry for the specified field name or value.
            String s = String.Format("Could not find watcher field name '{0}' or translation table does not contain an entry for '{1}'.  Please verify the configuration file is correct.", watcherFieldName, watcherFieldValue);
            Trace.TraceError(s);
            throw new ArgumentOutOfRangeException(s); 
        }

        #endregion

        #region Private Method(s)

        /// <summary>
        /// This method removes all translation and mapping information.
        /// </summary>
        private void Clear()
        {
            ExportMap.Reset();
            Translation.Clear();
        }

        /// <summary>
        /// Attempt to load the adapter configuration file from the filesystem.  If no file exists,
        /// or the load otherwise fails, attempt the same from the embedded configuration file.
        /// </summary>
        private void LoadInternal()
        {
            // Attempt to load the user's Watcher to Team Foundation mappings.
            LoadFromFile();
            if (_configurationDocument != null)
            {
                Trace.TraceInformation("Team Foundation adapter configuration loaded successfully.");
                return;
            }

            Trace.TraceWarning("Team Foundation adapter user configuration does not appear to exist or cannot be loaded.");

            // If the configuration does not exist in the installation directory,
            // load the embedded default configuration.
            LoadFromEmbedded();
            if (_configurationDocument != null)
            {
                Trace.TraceInformation("Team Foundation adapter configuration loaded successfully.");
            }

            String s = String.Format("Unable to load Team Foundation Adapter configuration.  Please ensure the file \"{0}\" exists in the Watcher installation directory.", Resources.AdapterConfigurationFile);
            Trace.TraceError(s);
            throw new WatcherException(s);
        }

        /// <summary>
        /// </summary>
        /// <returns></returns>
        private void LoadFromFile()
        {
            try
            {
                Trace.TraceInformation("Loading the Team Foundation user configuration.");

                // Attempt to load the Team Foundation adapter configuration
                String mappingPath = String.Format(@"{0}\{1}", Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), Resources.AdapterConfigurationFile);
                if (File.Exists(mappingPath))
                {
                    Trace.TraceInformation("Loading the adapter configuration from '{0}'.", mappingPath);
                    _configurationDocument = XDocument.Load(mappingPath);
                }
            }

            catch (Exception ex)
            {
                // These exceptions are recoverable
                if (ex is SecurityException || ex is ArgumentException || ex is FileNotFoundException || ex is UriFormatException)
                {
                    Trace.TraceError("Exception: {0}", ex.Message);
                }

                // Unrecoverable exceptions are rethrown
                throw;
            }

            finally
            {
                if (_configurationDocument == null)
                {
                    Trace.TraceWarning("Failed to load the Team Foundation user configuration.");
                }
            }
        }

        /// <summary>
        /// </summary>
        private void LoadFromEmbedded()
        {
            try
            {
                Trace.TraceInformation("Loading the Team Foundation embedded configuration.");
                _configurationDocument = XDocument.Parse(Resources.Watcher_TeamFoundation);
            }

            catch (Exception ex)
            {
                // These exceptions are recoverable
                if (ex is SecurityException || ex is ArgumentException || ex is FileNotFoundException || ex is UriFormatException)
                {
                    Trace.TraceError("Exception: {0}", ex.Message);
                }

                // Unrecoverable exceptions are rethrown
                throw;
            }

            finally
            {
                if (_configurationDocument == null)
                {
                    Trace.TraceWarning("Failed to load the Team Foundation embedded configuration.");
                }
            }
        }

        #endregion
    }
}
