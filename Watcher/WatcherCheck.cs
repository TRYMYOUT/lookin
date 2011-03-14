// WATCHER
//
// WatcherCheck.cs
// Main implementation of WatcherCheck Class.
//
// Copyright (c) 2010 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Diagnostics;
using System.Text;
using Fiddler;

namespace CasabaSecurity.Web.Watcher
{
    /// <summary>
    /// This type represents the severity of the alert generated by a Watcher check.
    /// </summary>
    /// <remarks>
    /// TODO: Move this to WatcherResult.cs
    /// </remarks>
    public enum WatcherResultSeverity
    {
        Informational   = 0,
        Low             = 1,
        Medium          = 2,
        High            = 3
    }

    /// <summary>
    /// This type represents a check's conformance with standards implemented by Watcher.
    /// </summary>
    [Flags]
    public enum WatcherCheckStandardsCompliance
    {
        None                           = 0x0000,    // The check is not comformant with a standard implemented by Watcher
        OwaspAppSecVerificationLevel1  = 0x0001,    // The check conforms to OWASP Application Security Verification Level 1A -and- 1B
        OwaspAppSecVerificationLevel1A = 0x0002,    // The check conforms to OWASP ASVL 1A
        OwaspAppSecVerificationLevel1B = 0x0003,    // ...
        OwaspAppSecVerificationLevel2  = 0x0008,    // The check conforms to OWASP ASVL 2A -and- 2B
        OwaspAppSecVerificationLevel2A = 0x0010,    // ...
        OwaspAppSecVerificationLevel2B = 0x0020,
        OwaspAppSecVerificationLevel3  = 0x0030,
        OwaspAppSecVerificationLevel4  = 0x0080,
        MicrosoftSdl                   = 0x0100,    // The check conforms to a Microsoft SDL requirement or recommendation.
    }

    /// <summary>
    /// This type represents some category of technology or actions a check is concerned with.
    /// </summary>
    [Flags]
    public enum WatcherCheckCategory
    {
        None                            = 0x0000,   // The check doesn't have a category defined.
        AspNet                          = 0x0005,   // The check relates to ASP.NET
        Charset                         = 0x0010,   // The check relates to charsets.
        Cookie                          = 0x0020,   // The check relates to HTTP cookies.
        CrossDomain                     = 0x0030,   // The check relates to cross-domain interactions.
        Flash                           = 0x0040,   // The check relates to Adobe Flash.
        Header                          = 0x0060,   // The check relates to HTTP headers.
        InfoDisclosure                  = 0x0080,   // The check relates to information disclosure.
        Java                            = 0x0100,   // The check relates to Java.
        JavaScript                      = 0x0140,   // The check relates to JavaScript.
        Sharepoint                      = 0x0180,   // The check relates to Sharepoint.
        Silverlight                     = 0x0220,   // The check relates to Silverlight.
        Ssl                             = 0x0260,   // The check relates to SSL.
        Unicode                         = 0x0280,   // The check relates to Unicode.
        UserControlled                  = 0x0300,   // The check relates to user-controlled events.
    }


    /// <summary>
    /// This is the base class for Watcher Checks, which includes a set of virtual
    /// functions that should be implemented by checks.
    /// </summary>
    public abstract class WatcherCheck
    {
        Stopwatch sw = new Stopwatch();
        #region Fields
        public Boolean _enabled = true;                                 // Is this check enabled?
        private Boolean _noisy = false;                                  // Does the check generate a lot of noise?
        public int historysize = 1000;
        private String _shortName = string.Empty;
        private String _longName = string.Empty;
        private String _shortDescription = string.Empty;
        private String _longDescription = string.Empty;
        private String _reference = string.Empty;
        private String _recommendation = string.Empty;
        private WatcherCheckStandardsCompliance _standardsCompliance;   // Standards implemented by Watcher that this check conforms to
        private WatcherCheckCategory _checkCategory;                    // How to categorize the check.
        #endregion

        #region Ctor(s)

        protected WatcherCheck()
        {
        }
        #endregion

        #region Dtor(s)
        #endregion

        #region Public Properties

        /// <summary>
        /// Returns True if the check is enabled, False otherwise.
        /// </summary>
        public Boolean Enabled
        {
            get { return _enabled; }
            set { _enabled = value; }
        }

        /// <summary>
        /// Set to true if the check will generate a lot of noise/results.  
        /// Users may want to disable it based on this information, but ideally
        /// the check author would implement some sort of noise-reduction filter.
        /// </summary>
        protected Boolean Noisy
        {
            get { return _noisy; }
            set { _noisy = value; }
        }

        /// <summary>
        /// Short name used in the results and findings.
        /// </summary>
        protected String ShortName
        {
            get { return _shortName; }
            set { _shortName = value; }
        }

        /// <summary>
        /// Short description used in places like the findings and results.
        /// </summary>
        protected String ShortDescription
        {
            get { return _shortDescription; }
            set { _shortDescription = value; }
        }

        /// <summary>
        /// Long name used in places like the main check configuration screen.
        /// </summary>
        protected String LongName
        {
            get { return _longName; }
            set { _longName = value; }
        }

        /// <summary>
        /// Long description used in places like the main check configuration.
        /// </summary>
        protected String LongDescription
        {
            get { return _longDescription; }
            set { _longDescription = value; }
        }

        /// <summary>
        /// The external reference that give more information about the check,
        /// should go to the CodePlex wiki site.
        /// </summary>
        protected String Reference
        {
            get { return _reference; }
            set { _reference = value; }
        }

        /// <summary>
        /// Any recommendation for how to mitigate or defend against the issue.
        /// </summary>
        protected String Recommendation
        {
            get { return _recommendation; }
            set { _recommendation = value; }
        }

        /// <summary>
        /// Returns a bitmask of the category or categories that a check belongs to.
        /// </summary>
        public WatcherCheckCategory CheckCategory
        {
            get { return _checkCategory; }
            protected set { _checkCategory = value; }

        }

        /// <summary>
        /// Returns a bitmask of standards implemented by Watcher that this check conforms to.
        /// </summary>
        public WatcherCheckStandardsCompliance StandardsCompliance
        {
            get { return _standardsCompliance; }
            protected set { _standardsCompliance = value; }
        }

        #endregion

        #region Public Methods

        public virtual void Clear()
        {
        }

        public virtual String GetShortName()
        {
            return this.ShortName;
        }

        public virtual String GetName()
        {
            return this.LongName;
        }

        public virtual String GetDescription()
        {
            return this.LongDescription;
        }

        public virtual String GetRefLink()
        {
            return this.Reference;
        }

        public virtual System.Windows.Forms.Panel GetConfigPanel()
        {
            return null;
        }

        // This function should be thread safe
        // TODO: POTENTIALLY BREAKING CHANGE: Method signature: removal of Watcher parameter, UtilityHtmlParser parameter
        public abstract void Check(Session session);

        /// <summary>
        /// Start a stopwatch.
        /// </summary>
        public void Start()
        {
            sw.Reset();
            sw.Start();
        }

        /// <summary>
        /// Stop the stopwatch.
        /// </summary>
        /// <param name="url">The URL of the current session.</param>
        public void End(String url)
        {
            sw.Stop();
            if (sw.ElapsedMilliseconds > 0)
            {
                Debug.Print("[*] In Check Timing:{0}:{1}:{2}.", GetShortName(), sw.ElapsedMilliseconds, url);
            }
        }
        public virtual void UpdateWordList()
        {
        }

        public override string ToString()
        {
            return GetName();
        }

        /// <summary>
        /// This method returns a string representative of the standards to which this check complies.
        /// </summary>
        public virtual String GetStandardsComplianceString()
        {
            StringBuilder standardsCompliance = new StringBuilder();

            #region OWASP Standards

            // If the check is compliant with the specified standard, add the canonical name (retrieved 
            // from the resource file) of the standard to the string returned.
            if (IsCompliant(WatcherCheckStandardsCompliance.MicrosoftSdl))
            {
                standardsCompliance.AppendFormat("{0}, ", GetResourceComplianceString(WatcherCheckStandardsCompliance.MicrosoftSdl));
            }

            if (IsCompliant(WatcherCheckStandardsCompliance.OwaspAppSecVerificationLevel1))
            {
                standardsCompliance.AppendFormat("{0}, ", GetResourceComplianceString(WatcherCheckStandardsCompliance.OwaspAppSecVerificationLevel1));
            }

            // ... and do this for each standards compliance flag ...
            if (IsCompliant(WatcherCheckStandardsCompliance.OwaspAppSecVerificationLevel1A))
            {
                standardsCompliance.AppendFormat("{0}, ", GetResourceComplianceString(WatcherCheckStandardsCompliance.OwaspAppSecVerificationLevel1A));
            }

            if (IsCompliant(WatcherCheckStandardsCompliance.OwaspAppSecVerificationLevel1B))
            {
                standardsCompliance.AppendFormat("{0}, ", GetResourceComplianceString(WatcherCheckStandardsCompliance.OwaspAppSecVerificationLevel1B));
            }

            if (IsCompliant(WatcherCheckStandardsCompliance.OwaspAppSecVerificationLevel2))
            {
                standardsCompliance.AppendFormat("{0}, ", GetResourceComplianceString(WatcherCheckStandardsCompliance.OwaspAppSecVerificationLevel2));
            }

            if (IsCompliant(WatcherCheckStandardsCompliance.OwaspAppSecVerificationLevel2A))
            {
                standardsCompliance.AppendFormat("{0}, ", GetResourceComplianceString(WatcherCheckStandardsCompliance.OwaspAppSecVerificationLevel2A));
            }

            if (IsCompliant(WatcherCheckStandardsCompliance.OwaspAppSecVerificationLevel2B))
            {
                standardsCompliance.AppendFormat("{0}, ", GetResourceComplianceString(WatcherCheckStandardsCompliance.OwaspAppSecVerificationLevel2B));
            }

            if (IsCompliant(WatcherCheckStandardsCompliance.OwaspAppSecVerificationLevel3))
            {
                standardsCompliance.AppendFormat("{0}, ", GetResourceComplianceString(WatcherCheckStandardsCompliance.OwaspAppSecVerificationLevel3));
            }

            if (IsCompliant(WatcherCheckStandardsCompliance.OwaspAppSecVerificationLevel4))
            {
                standardsCompliance.AppendFormat("{0}, ", GetResourceComplianceString(WatcherCheckStandardsCompliance.OwaspAppSecVerificationLevel4));
            }

            // If the check complies not to a standard, assume it complies to the None standard
            if (standardsCompliance.Length == 0)
            {
                standardsCompliance.AppendFormat("{0}", GetResourceComplianceString(WatcherCheckStandardsCompliance.None));
            }

            #endregion

            // Extract the string from the string builder, and remove the trailing separator characters
            // TODO: does this make a copy of the string? it should.
            String standardsComplianceDisplayed = standardsCompliance.ToString();
            standardsComplianceDisplayed = standardsComplianceDisplayed.TrimEnd(new char[] { ',', ' ' });

            // Clear the string builder
            // TODO: does this reallocate the string?
            standardsCompliance.Remove(0, standardsCompliance.Length);

            // Return the canonical list of standards to which this check complies
            return standardsComplianceDisplayed;
        }

        #endregion

        #region Private Method(s)

        /// <summary>
        /// This method retreives the user-visible, canonical description of the specified compliance flag from the resource file.
        /// </summary>
        /// <param name="e">The compliance flag to retrieve.</param>
        /// <returns>The canonical description of the specified standard.</returns>
        private String GetResourceComplianceString(WatcherCheckStandardsCompliance e)
        {
            return Properties.Resources.ResourceManager.GetString(String.Format("WatcherCheckStandardsCompliance_{0}", e.ToString()));
        }

        /// <summary>
        /// This method indicates whether the specified compliance flag is supported by this check.
        /// </summary>
        /// <param name="e">The compliance flag to check.</param>
        /// <returns>True if the check complies with the specified flag; False otherwise.</returns>
        private Boolean IsCompliant(WatcherCheckStandardsCompliance e)
        {
            return (StandardsCompliance & e) == e;
        }

        #endregion
    }
}