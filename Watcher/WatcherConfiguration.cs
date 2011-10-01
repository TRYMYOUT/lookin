// WATCHER
//
// WatcherConfiguration.cs
// Implements a wrapper for Watcher configuration operations.
//
// Copyright (c) 2010 Casaba Security, LLC
// All Rights Reserved.
//

// TODO: Save settings on exit (or ask)  Int32 level, Int32 ID, String URL, String typex, String description, Int32 count
// TODO: Assert _configuration != null when used in public methods

using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.Text;
using System.IO;
using System.Text.RegularExpressions;
using System.Windows.Forms;
using System.Reflection;

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
        private ConfigurationElement[] _copyconfig = null;
        private String _originDomain = String.Empty;                                        // Domain to be analyzed
        private Boolean _watcherEnabled = false;                                            // Is the Watcher enabled?
        private Boolean _autosave = false;
        private Boolean _autocheck = false;
        private System.Drawing.Color _backgroundcolor = System.Drawing.SystemColors.ControlLight;
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
            set
            {
                _originDomain = value; 
                if (_autosave)
                { 
                    Save(); 
                }
            }
        }

        /// <summary>
        /// The background color for Watcher UI.
        /// </summary>
        public System.Drawing.Color BackGroundColor
        {
            get { return _backgroundcolor; }
            set
            {
                _backgroundcolor = value;
                if (_autosave)
                {
                    Save();
                }
            }
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
            set { 
                _watcherEnabled = value;
                if (_autosave)
                {
                    Save();
                }
            }
        }

        /// <summary>
        /// Returns True if Watcher AutoSaves its config, False otherwise.
        /// </summary>
        public Boolean AutoSave
        {
            get { return _autosave; }
            set { _autosave = value; }
        }

        /// <summary>
        /// Returns True if Watcher auto-check is disabled, False otherwise.
        /// </summary>
        public Boolean AutoVerCheckDisabled
        {
            get { return _autocheck; }
            set { 
                _autocheck = value;
                if (_autosave)
                {
                    Save();
                }
            }
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
                PersistAutoSave();
                PersistAutoVerCheck();
                PersistBackGroundColor();

                // Save the configuration file.
                lock (_lock)
                {
                    _configuration.Save(ConfigurationSaveMode.Modified);
                }

                // Force a reload of a changed section.   
                ConfigurationManager.RefreshSection("appSettings");
                _copyconfig = new KeyValueConfigurationElement[_configuration.AppSettings.Settings.Count];
                _configuration.AppSettings.Settings.CopyTo(_copyconfig, 0);
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
                _copyconfig = new KeyValueConfigurationElement[_configuration.AppSettings.Settings.Count];
                _configuration.AppSettings.Settings.CopyTo(_copyconfig, 0);
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
                _copyconfig = new KeyValueConfigurationElement[_configuration.AppSettings.Settings.Count];
                _configuration.AppSettings.Settings.CopyTo(_copyconfig, 0);
            }
        }



        /// <summary>
        /// Get a configuration item with no default value set.
        /// </summary>
        /// <param name="check">The Watcher check whose configuration option is to be retrieved.</param>
        /// <param name="configOption">The configuration option to retrieve.</param>
        /// <returns>The value of the specified option.</returns>
        public String GetConfigItem(WatcherCheck check, String configOption)
        {
            return GetConfigItem(check, configOption, String.Empty);
        }


        /// <summary>
        /// Get a configuration item with no default value set.
        /// </summary>
        /// <param name="check">The Watcher plugin whose configuration option is to be retrieved.</param>
        /// <param name="configOption">The configuration option to retrieve.</param>
        /// <returns>The value of the specified option.</returns>
        public String GetConfigItem(WatcherOutputPlugin plugin, String configOption)
        {
            return GetConfigItem(plugin, configOption, String.Empty);
        }

        /// <summary>
        /// Get a configuration item and return the specified default value if not already present.
        /// </summary>
        /// <param name="check">The Watcher check whose configuration option is to be retrieved.</param>
        /// <param name="configOption">The configuration option to retrieve.</param>
        /// <param name="defaultValue">The value to return if not already set in the configuration.</param>
        /// <returns>The value of the specified check's configuration option.</returns>
        public String GetConfigItem(WatcherCheck check, String configOption, String defaultValue)
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
                        setting = Get(checkOptionName);// ConfigurationManager.AppSettings[checkOptionName];
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
                            SetConfigItem(check, configOption, defaultValue);
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
        /// Get a configuration item and return the specified default value if not already present.
        /// </summary>
        /// <param name="check">The Watcher check whose configuration option is to be retrieved.</param>
        /// <param name="configOption">The configuration option to retrieve.</param>
        /// <param name="defaultValue">The value to return if not already set in the configuration.</param>
        /// <returns>The value of the specified check's configuration option.</returns>
        public String GetConfigItem(WatcherOutputPlugin plugin, String configOption, String defaultValue)
        {
            // The name of the check as it is stored in the application configuration
            String configurationName = plugin.GetName();
            if (configurationName.Length > 0)
            {
                // Prepend Plugin Class to KeyName
                String pluginOptionName = configurationName + '\\' + configOption;
                if (!String.IsNullOrEmpty(configurationName))
                {
                    String setting = String.Empty;

                    try
                    {
                        // Load the check configuration from the application configuration
                        setting = Get(pluginOptionName);// ConfigurationManager.AppSettings[checkOptionName];
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
                            SetConfigItem(plugin, configOption, defaultValue);
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
            String configurationValue = Get(configurationName[configurationName.Length - 1]);//ConfigurationManager.AppSettings[configurationName[configurationName.Length - 1]];
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

            String checkstate = check.Enabled ? "True" : "False";
            // Store the check enabled/disabled state
            if (Get(configurationName[configurationName.Length - 1]) != checkstate)
            {
                Remove(configurationName[configurationName.Length - 1]);
                Add(configurationName[configurationName.Length - 1], check.Enabled ? "True" : "False");
                if (_autosave)
                {
                    Save();
                }
            }
        }

        /// <summary>
        /// Set a configuration option for the specified check.  An entry will be created if it doesn't already exist.
        /// </summary>
        /// <param name="check">The Watcher check whose configuration option is to be set.</param>
        /// <param name="configOption">The configuration option to set.</param>
        /// <param name="value">The configuration value to set.</param>
        public void SetConfigItem(WatcherCheck check, String configOption, String value)
        {
            String[] configurationName = GetCheckNameTokens(check);
            if (configurationName.Length > 0)
            {
                String checkOptionName = configurationName[configurationName.Length - 1] + "\\" + configOption;
                if (!String.IsNullOrEmpty(configurationName[configurationName.Length - 1]))
                {
                    Remove(checkOptionName);
                    Add(checkOptionName, value);
                    if (_autosave)
                    {
                        Save();
                    }
                }
            }
            // TODO: return a bool for success
        }

        /// <summary>
        /// Set a configuration option for the specified check.  An entry will be created if it doesn't already exist.
        /// </summary>
        /// <param name="check">The Watcher check whose configuration option is to be set.</param>
        /// <param name="configOption">The configuration option to set.</param>
        /// <param name="value">The configuration value to set.</param>
        public void SetConfigItem(WatcherOutputPlugin plugin, String configOption, String value)
        {
            String configurationName = plugin.GetName();
            if (configurationName.Length > 0)
            {
                String pluginOptionName = configurationName + "\\" + configOption;
                if (!String.IsNullOrEmpty(configurationName))
                {
                    Remove(pluginOptionName);
                    Add(pluginOptionName, value);
                    if (_autosave)
                    {
                        Save();
                    }
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

        /// <summary>
        /// This overload checks if the domain name passed in matches the origin domain configured by
        /// the user.  If an origin domain was not configured, then this check's allows an origin domain
        /// to be assumed by Watcher, specified through the two parameters.  Expected use:
        ///           IsOriginDomain(session.hostname, session.hostname)
        /// </summary>
        /// <param name="domain">The session hostname of the response.</param>
        /// <param name="responsedomain">Also the session hostname of the response.</param>
        /// <returns>True if the two parameters match, false otherwise.</returns>
        public Boolean IsOriginDomain(String domain, String responsedomain )
        {
            if (String.IsNullOrEmpty(OriginDomain))
            {
                String _responsedomain = responsedomain.Trim().ToLower();
                String _domain = domain.Trim().ToLower();
                return (Regex.IsMatch(_domain, _responsedomain));
            }

            String regex = OriginDomain.Trim().ToLower().Replace(".", "\\.").Replace("*", ".*");
            return Regex.IsMatch(domain, regex);
        }

        /// <summary>
        /// Get a list of the configured trusted domains as a string.
        /// </summary>
        /// <returns>Comma-separated list of configured trusted domains.</returns>
        public String GetTrustedDomainsAsString()
        {
            string doms = "";
            foreach (string trustedDomain in TrustedDomains)
            {
                doms = String.Concat(doms, trustedDomain, ",");
            }

            return doms.TrimEnd(new Char[] { ',' });
        }

        #endregion

        /// <summary>
        /// This method returns an string containing config value
        /// </summary>
        /// <param name="check">The Watcher check whose name is to be split.</param>
        /// <returns>The config value specified by a string.</returns>
        public String Get(String configname)
        {
            // Instance members of the Configuration class are not guaranteed thread-safe
            lock (_lock)
            {
                if (!String.IsNullOrEmpty(configname))
                {
                    foreach (KeyValueConfigurationElement element in _copyconfig)
                    {
                        if (element.Key == configname)
                        {
                            return element.Value;
                        }
                    }
                    /*
                    KeyValueConfigurationElement config = _configuration.AppSettings.Settings[configname];
                    if (config != null)
                    {
                        return config.Value;
                    }*/
                }
                return String.Empty;
            }
        }

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
                            String path = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location + "\\");
                            // Retrieve a configuration object so that our settings can be saved
                            _configuration = ConfigurationManager.OpenExeConfiguration(path);
                            _copyconfig = new KeyValueConfigurationElement[_configuration.AppSettings.Settings.Count];
                            _configuration.AppSettings.Settings.CopyTo(_copyconfig, 0);
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
            LoadWatcherAutoSave();
            LoadWatcherAutoVerCheck();
            LoadOriginDomain();
            LoadTrustedDomains();
            LoadWatcherBackGroundColor();
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
                setting = Get("TrustedDomains");
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
                String setting = Get("OriginDomain"); //ConfigurationManager.AppSettings["OriginDomain"];
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
                String setting = Get("Enable");//ConfigurationManager.AppSettings["Enable"];
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
        /// This method determines the Watcher background color and caches the result.
        /// </summary>
        private void LoadWatcherBackGroundColor()
        {
            try
            {
                // Set the Background Color if it is set in the configuration
                String setting = Get("BackGroundColor"); //ConfigurationManager.AppSettings["BackGroundColor"];
                if (!String.IsNullOrEmpty(setting))
                {
                    setting = Utility.Base64Decode(setting);
                    _backgroundcolor = System.Drawing.ColorTranslator.FromHtml(setting);
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
        /// This method determines if AutoSave is enabled in the application
        /// configuration and caches the result.
        /// </summary>
        private void LoadWatcherAutoSave()
        {
            try
            {
                // Set the "AutoSave" flag if it is set in the configuration
                String setting = Get("AutoSave");// ConfigurationManager.AppSettings["AutoSave"];
                _autosave = (setting == "True");
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
        /// This method determines if AutoSave is enabled in the application
        /// configuration and caches the result.
        /// </summary>
        private void LoadWatcherAutoVerCheck()
        {
            try
            {
                // Set the "AutoVerCheck" flag if it is set in the configuration
                String setting = Get("AutoVerCheck");  //ConfigurationManager.AppSettings["AutoVerCheck"];
                _autocheck = (setting == "True");
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

        /// <summary>
        /// This method adds the cached AutoSave property to the application configuration.
        /// </summary>
        private void PersistAutoSave()
        {
            Remove("AutoSave");
            Add("Autosave", _autosave ? "True" : "False");
        }

        /// <summary>
        /// This method adds the cached BackGround Color property to the application configuration.
        /// </summary>
        private void PersistBackGroundColor()
        {
            Remove("BackGroundColor");
            String setting = System.Drawing.ColorTranslator.ToHtml(_backgroundcolor);
            Add("BackGroundColor", Utility.Base64Encode(setting));
        }

        /// <summary>
        /// This method adds the cached AutoVerCheck property to the application configuration.
        /// </summary>
        private void PersistAutoVerCheck()
        {
            Remove("AutoVerCheck");
            Add("AutoVerCheck", _autocheck ? "True" : "False");
        }

        #endregion
    }
}
