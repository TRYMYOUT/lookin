// WATCHER
//
// WatcherConfiguration.cs
// Implements a wrapper for Watcher configuration operations.
//
// Copyright (c) 2009 Casaba Security, LLC
// All Rights Reserved.
//

// TODO: Save settings on exit (or ask)  Int32 level, Int32 ID, String URL, String typex, String description, Int32 count
// TODO: Assert _configuration != null when used in public methods

using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;

using CasabaSecurity.Web.Watcher.Collections;

namespace CasabaSecurity.Web.Watcher
{
    /// <summary>
    /// This class implements the Watcher Configuration Manager.
    /// </summary>
    public sealed class WatcherConfiguration
    {
        #region Fields
        private static Object _lock = new Object();                                         // Use this to synchronize operations
        private TrustedDomainCollection _trustedDomains = new TrustedDomainCollection();    // Domains that are considered friendly
        private Configuration _configuration = null;                                        // System configuration object
        private String _originDomain = String.Empty;                                        // Domain to be analyzed
        private Boolean _watcherEnabled = false;                                            // Is the Watcher enabled?
        #endregion

        #region Ctor(s)
        public WatcherConfiguration()
        {
        }
        #endregion

        #region Public Properties

        /// <summary>
        /// This domain whose traffic will be monitored.
        /// </summary>
        public String OriginDomain
        {
            get { return _originDomain; }
            set { _originDomain = value; }
        }

        /// <summary>
        /// These domains are considered "friendly" and will not be flagged for potential issues.
        /// </summary>
        public TrustedDomainCollection TrustedDomains
        {
            // TODO: ReadOnlyCollection? With Find?
            get { return _trustedDomains; }
        }

        /// <summary>
        /// Returns True if Watcher is enabled, False otherwise.
        /// </summary>
        public Boolean Enabled
        {
            get { return _watcherEnabled; }
            set { _watcherEnabled = value; }
        }

        #endregion

        #region Public Method(s)

        /// <summary>
        /// Load the basic settings from the configuration: whether or not the extension is enabled, the trusted domain list, and the origin domain.
        /// </summary>
        public void Load()
        {
            OpenConfiguration();
            LoadConfigurationSettings();
        }

        /// <summary>
        /// Save the current configuration to the application's configuration file.
        /// </summary>
        public void Save()
        {
            try
            {
                // Store the cached settings prior to saving.
                PersistOriginDomain();
                PersistTrustedDomains();
                PersistWatcherEnabled();

                // Save the configuration file.
                lock (_lock)
                {
                    _configuration.Save(ConfigurationSaveMode.Modified);
                }

                // Force a reload of a changed section.   
                ConfigurationManager.RefreshSection("appSettings");
            }

            catch (ConfigurationErrorsException e)
            {
                // TODO: Notify the user that the configuration may not have been saved
                // Thrown if a failure occurs when reading the application configuration
                String errorMessage = String.Format("Error: ConfigurationErrorsException: {0}", e.Message);
                Trace.TraceError("Error: {0}", errorMessage);
                Debug.Assert(false, errorMessage);
            }
        }

        /// <summary>
        /// Add a new configuration setting key/value pair.
        /// </summary>
        /// <param name="key">The name of the parameter to set.</param>
        /// <param name="value">The value of the parameter to set.</param>
        public void Add(String key, String value)
        {
            // Instance members of the Configuration class are not guaranteed thread-safe
            lock (_lock)
            {
                _configuration.AppSettings.Settings.Add(key, value);
            }
        }

        /// <summary>
        /// Remove the specified key from the application configuration file.
        /// </summary>
        /// <param name="key">The name of the key to remove.</param>
        public void Remove(String key)
        {
            // Instance members of the Configuration class are not guaranteed thread-safe
            lock (_lock)
            {
                _configuration.AppSettings.Settings.Remove(key);
            }
        }

        /// <summary>
        /// Get a configuration item with no default value set.
        /// </summary>
        /// <param name="check">The Watcher check whose configuration option is to be retrieved.</param>
        /// <param name="configOption">The configuration option to retrieve.</param>
        /// <returns>The value of the specified option.</returns>
        public String GetCheckConfig(WatcherCheck check, String configOption)
        {
            return GetCheckConfig(check, configOption, String.Empty);
        }

        /// <summary>
        /// Get a configuration item and return the specified default value if not already present.
        /// </summary>
        /// <param name="check">The Watcher check whose configuration option is to be retrieved.</param>
        /// <param name="configOption">The configuration option to retrieve.</param>
        /// <param name="defaultValue">The value to return if not already set in the configuration.</param>
        /// <returns>The value of the specified check's configuration option.</returns>
        public String GetCheckConfig(WatcherCheck check, String configOption, String defaultValue)
        {
            // The name of the check as it is stored in the application configuration
            String[] configurationName = GetCheckNameTokens(check);
            if (configurationName.Length > 0)
            {
                // Prepend Check Class to KeyName
                String checkOptionName = configurationName[configurationName.Length - 1] + '\\' + configOption;
                if (!String.IsNullOrEmpty(configurationName[configurationName.Length - 1]))
                {
                    String setting = String.Empty;

                    try
                    {
                        // Load the check configuration from the application configuration
                        setting = ConfigurationManager.AppSettings[checkOptionName];
                    }

                    catch (ConfigurationErrorsException e)
                    {
                        // Thrown if a failure occurs when reading the application configuration
                        String errorMessage = String.Format("Error: ConfigurationErrorsException: {0}", e.Message);
                        Trace.TraceError("Error: {0}", errorMessage);
                        Debug.Assert(false, errorMessage);
                    }

                    // If the configuration entry for the check does not exist, use the default value
                    if (String.IsNullOrEmpty(setting))
                    {
                        // Set the default value if it was specified
                        if (!String.IsNullOrEmpty(defaultValue))
                        {
                            SetCheckConfig(check, configOption, defaultValue);
                        }

                        return defaultValue;
                    }

                    // Note: checking a second time does not get an updated setting
                    return setting;
                }
            }

            return String.Empty;
        }

        /// <summary>
        /// This method determines if the specified check is enabled in the configuration.  If it is
        /// not, it creates an entry for the check in the application configuration using the default
        /// setting retrieved from the check's Enabled property.
        /// </summary>
        /// <remarks>TODO: Check names can collide</remarks>
        /// <param name="check">The check whose status is to be retrieved.</param>
        /// <returns>True if the check is enabled; False if it is not.  The check's default (Check.Enabled) is returned if the check did not exist in the configuration.</returns>
        public Boolean GetCheckEnabledConfig(WatcherCheck check)
        {
            // Determine the name of the check configuration entry from its type
            String[] configurationName = GetCheckNameTokens(check);

            // Default: the check's enabled/disabled value
            Boolean enabled = check.Enabled;

            // Determine the check's value from the configuration, if it has been set
            String configurationValue = ConfigurationManager.AppSettings[configurationName[configurationName.Length - 1]];
            if (String.IsNullOrEmpty(configurationValue))
            {
                // TODO: Trace addition of configuration option
                // The item doesn't exist in the configuration, use the check's default enabled/disabled value
                Add(configurationName[configurationName.Length - 1], enabled ? "True" : "False");
            }
            else
            {
                enabled = (configurationValue == "True");
            }

            return enabled;
        }

        /// <summary>
        /// This method sets the enabled/disabled state of the check in the application configuration.
        /// </summary>
        /// <remarks>TODO: Names can collide</remarks>
        /// <param name="check">The check whose status is to be stored.</param>
        public void SetCheckEnabledConfig(WatcherCheck check)
        {
            // Determine the name of the check entry from its type
            String[] configurationName = GetCheckNameTokens(check);

            // Store the check enabled/disabled state
            Remove(configurationName[configurationName.Length - 1]);
            Add(configurationName[configurationName.Length - 1], check.Enabled ? "True" : "False");
        }

        /// <summary>
        /// Set a configuration option for the specified check.  An entry will be created if it doesn't already exist.
        /// </summary>
        /// <param name="check">The Watcher check whose configuration option is to be set.</param>
        /// <param name="configOption">The configuration option to set.</param>
        /// <param name="value">The configuration value to set.</param>
        public void SetCheckConfig(WatcherCheck check, String configOption, String value)
        {
            String[] configurationName = GetCheckNameTokens(check);
            if (configurationName.Length > 0)
            {
                String checkOptionName = configurationName[configurationName.Length - 1] + "\\" + configOption;
                if (!String.IsNullOrEmpty(configurationName[configurationName.Length - 1]))
                {
                    Remove(checkOptionName);
                    Add(checkOptionName, value);
                }
            }
            // TODO: return a bool for success
        }

        /// <summary>
        /// This method returns True if the specified domain matches a Trusted Domain regex.
        /// </summary>
        /// <param name="domain">The domain to search for in the list of Trusted Domains.</param>
        /// <returns>True if the domain was found in the list of Trusted Domains; False if not.</returns>
        public Boolean IsTrustedDomain(String domain)
        {
            String currentRegex = String.Empty;     

            // Enumerate the Trusted Domains and compare each as a regex against the specified domain.
            foreach (String trustedDomain in TrustedDomains)
            {
                currentRegex = trustedDomain.Trim().ToLower().Replace(".", "\\.").Replace("*", ".*");
                if (Regex.IsMatch(domain, currentRegex))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// This method returns True if the specified domain matches the Origin Domain.
        /// </summary>
        /// <remarks>TODO: This is hideously ugly, but we wanted to support regex for some reason rather than wild carded item names.</remarks>
        /// <param name="domain">The host name to compare to the Origin Domain.</param>
        /// <returns>True if the given name matches the Origin Domain or the Origin Domain is empty; False if otherwise.</returns>
        public Boolean IsOriginDomain(String domain)
        {
            if (String.IsNullOrEmpty(OriginDomain))
            {
                return true;
            }

            String regex = OriginDomain.Trim().ToLower().Replace(".", "\\.").Replace("*", ".*");
            return Regex.IsMatch(domain, regex);
        }

        #endregion

        #region Private Method(s)

        /// <summary>
        /// This method returns an array of strings representing each level in the fully-qualified
        /// type-name heirarchy.
        /// </summary>
        /// <remarks>TODO: This should probably not return an array.</remarks>
        /// <param name="check">The Watcher check whose name is to be split.</param>
        /// <returns>An array of strings representing each level in the fully-qualified type-name heirarchy.</returns>
        private String[] GetCheckNameTokens(WatcherCheck check)
        {
            String[] tokens = check.GetType().ToString().Split('.');
            
            // Make sure the tokenization was sane
            if (tokens.Length < 1)
            {
                String errorMessage = String.Format("The name of the check could not be determined ({0}).", check.GetType());
                Trace.TraceError("Error: {0}", errorMessage);
                Debug.Assert(false, errorMessage);
                return new String[] { String.Empty }; // Prevent null reference exceptions by callers doing indexing
            }

            return tokens;
        }

        /// <summary>
        /// This method opens the application configuration.
        /// </summary>
        private void OpenConfiguration()
        {
            // The configuration should only be opened once
            if (_configuration != null)
            {
                String errorMessage = "An instance of the configuration already exists.";
                Trace.TraceError(String.Format("Error: {0}", errorMessage));
                Debug.Assert(false, errorMessage);
                throw new InvalidOperationException(errorMessage);
            }

            // If the configuration hasn't been opened, attempt to open it, and handle
            // any other threads that may be attempting to open it at the same time.
            if (_configuration == null)
            {
                lock (_lock)
                {
                    if (_configuration == null)
                    {
                        try
                        {
                            // Retrieve a configuration object so that our settings can be saved
                            _configuration = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None);
                        }

                        catch (ConfigurationErrorsException e)
                        {
                            // Thrown if a failure occurs when reading the application configuration
                            String errorMessage = String.Format("ConfigurationErrorsException: {0}", e.Message);
                            Trace.TraceError("Error: {0}", errorMessage);
                            Debug.Assert(false, errorMessage);
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Load the application settings and cache them.
        /// </summary>
        private void LoadConfigurationSettings()
        {
            LoadWatcherEnabled();
            LoadOriginDomain();
            LoadTrustedDomains();
        }

        /// <summary>
        /// This method determines the Trusted Domains set in the application configuration and
        /// caches them.
        /// </summary>
        private void LoadTrustedDomains()
        {
            String setting = String.Empty;

            try
            {
                // Decode the Trusted Domains stored in the configuration and add them to the Trusted Domain list
                setting = ConfigurationManager.AppSettings["TrustedDomains"];
                if (String.IsNullOrEmpty(setting))
                {
                    Trace.TraceWarning("Warning: Trusted Domains list not found in the configuration.");
                    return;
                }
            }

            catch (ConfigurationErrorsException e)
            {
                // Thrown if a failure occurs when reading the application configuration
                String errorMessage = String.Format("ConfigurationErrorsException: {0}", e.Message);
                Trace.TraceError("Error: {0}", errorMessage);
                Debug.Assert(false, errorMessage);

                // No need to continue
                return;
            }

            // Enumerate the encoded Trusted Domains from the application settings
            String[] encodedDomains = setting.Split(new char[] { ',' });
            foreach (String encodedDomain in encodedDomains)
            {
                // Decode the encoded domain
                String trustedDomain = Utility.Base64Decode(encodedDomain);
                if (trustedDomain.Length == 0)
                {
                    Trace.TraceWarning("Warning: Not adding empty item to Trusted Domains list.");
                    continue;
                }

                // Add the decoded domain to the Trusted Domain list if it doesn't already exist
                if (TrustedDomains.Contains(trustedDomain) == false)
                {
                    TrustedDomains.Add(trustedDomain);
                }
            }
        }

        /// <summary>
        /// This method determines the if configured Origin Domain is set in the application
        /// configuration and caches the result.
        /// </summary>
        private void LoadOriginDomain()
        {
            try
            {
                // Set the Origin Domain if it exists in the configuration
                String setting = ConfigurationManager.AppSettings["OriginDomain"];
                if (setting != null)
                {
                    _originDomain = Utility.Base64Decode(setting);
                }
            }

            catch (ConfigurationErrorsException e)
            {
                // Thrown if a failure occurs when reading the application configuration
                String errorMessage = String.Format("ConfigurationErrorsException: {0}", e.Message);
                Trace.TraceError("Error: {0}", errorMessage);
                Debug.Assert(false, errorMessage);
            }
        }

        /// <summary>
        /// This method determines if the Watcher extension is enabled in the application
        /// configuration and caches the result.
        /// </summary>
        private void LoadWatcherEnabled()
        {
            try
            {
                // Set the "Watcher Enabled" flag if it is set in the configuration
                String setting = ConfigurationManager.AppSettings["Enable"];
                _watcherEnabled = (setting == "True");
            }

            catch (ConfigurationErrorsException e)
            {
                // Thrown if a failure occurs when reading the application configuration
                String errorMessage = String.Format("ConfigurationErrorsException: {0}", e.Message);
                Trace.TraceError("Error: {0}", errorMessage);
                Debug.Assert(false, errorMessage);
            }
        }

        /// <summary>
        /// This method adds the cached TrustedDomains list to the application configuration.
        /// </summary>
        /// <remarks>TODO: This is a somewhat inefficient, i.e. the entire list may not need to be removed/re-added</remarks>
        private void PersistTrustedDomains()
        {
            Remove("TrustedDomains");

            // Base64 encode each of the domains for storage
            TrustedDomainCollection encodedDomainList = new TrustedDomainCollection(TrustedDomains.Count);
            foreach (String trustedDomain in TrustedDomains)
            {
                encodedDomainList.Add(Utility.Base64Encode(trustedDomain));
            }

            Add("TrustedDomains", String.Join(",", encodedDomainList.ToArray()));
        }

        /// <summary>
        /// This method adds the cached OriginDomain to the application configuration.
        /// </summary>
        private void PersistOriginDomain()
        {
            Remove("OriginDomain");
            Add("OriginDomain", Utility.Base64Encode(_originDomain));
        }

        /// <summary>
        /// This method adds the cached WatcherEnabled property to the application configuration.
        /// </summary>
        private void PersistWatcherEnabled()
        {
            Remove("Enable");
            Add("Enable", _watcherEnabled ? "True" : "False");
        }

        #endregion
    }
}
