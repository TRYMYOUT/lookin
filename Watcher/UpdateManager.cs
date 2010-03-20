// WATCHER
//
// VersionCheck.cs
// Implements the VersionCheck class.
//
// Copyright (c) 2010 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Collections.Generic;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace CasabaSecurity.Web.Watcher
{
    /// <summary>
    /// This class performs logic related to product updates.
    /// </summary>
    internal sealed class UpdateManager
    {
        #region Fields
        private Version _CurrentVersionEngine = null;
        private Version _CurrentVersionCheckLib = null;
        private Version _LatestVersionEngine = new Version();
        private Version _LatestVersionCheckLib = new Version();
        private String _LatestVersionReleaseNotes = String.Empty;
        #endregion

        #region Ctor(s)
        /// <remarks>
        /// Default public constructors should always be defined.
        /// </remarks>
        public UpdateManager()
        {
        }
        #endregion

        #region Public Properties
        /// <summary>
        /// This property determines the current version of the product (not including the check library; not
        /// including the Revision).  The Revision number is removed from the result as the web site does not 
        /// provide this information.
        /// </summary>
        public Version CurrentVersionEngine
        {
            get
            {
                if (_CurrentVersionEngine == null)
                {
                    Version AsmVersion = Assembly.GetExecutingAssembly().GetName().Version;
                    _CurrentVersionEngine = new Version(AsmVersion.Major, AsmVersion.Minor, AsmVersion.Build);
                }
                return _CurrentVersionEngine;
            }
        }

        /// <summary>
        /// This property determines the current version of the CheckLib (not
        /// including the Revision).  The Revision number is removed from the result as the web site does not 
        /// provide this information.
        /// </summary>
        public Version CurrentVersionCheckLib
        {
            get
            {
                if (_CurrentVersionCheckLib == null)
                {
                    System.Reflection.Assembly[] assemblylist = AppDomain.CurrentDomain.GetAssemblies();
                    foreach (Assembly i in assemblylist)
                    {
                        if (i.FullName.Contains("CasabaSecurity.Web.Watcher.Checks"))
                        {
                            Version AsmVersion = i.GetName().Version;
                            _CurrentVersionCheckLib = new Version(AsmVersion.Major, AsmVersion.Minor, AsmVersion.Build);
                        }
                    }
                }
                return _CurrentVersionCheckLib;
            }
        }

        /// <summary>
        /// This property determines if updates are available.
        /// </summary>
        public Boolean IsUpdateAvailable
        {
            get { return LatestVersionEngine.CompareTo(CurrentVersionEngine) > 0 || LatestVersionCheckLib.CompareTo(CurrentVersionCheckLib) > 0; }
        }

        /// <summary>
        /// This property returns the latest version available from the product web site.
        /// </summary>
        public Version LatestVersionEngine
        {
            get { return _LatestVersionEngine; }
            private set { _LatestVersionEngine = value; }
        }

        /// <summary>
        /// This property returns the latest version available from the product web site.
        /// </summary>
        public Version LatestVersionCheckLib
        {
            get { return _LatestVersionCheckLib; }
            private set { _LatestVersionCheckLib = value; }
        }

        /// <summary>
        /// This property returns the latest version of the release notes retrieved from the
        /// product web site on the last refresh.
        /// </summary>
        public String LatestVersionReleaseNotes
        {
            get { return _LatestVersionReleaseNotes; }
            private set { _LatestVersionReleaseNotes = value; }
        }
        #endregion

        #region Private Callback(s)

        /// <summary>
        /// This delegate is used to perform the update check asynchronously.
        /// </summary>
        private delegate void GetLatestVersionMetadataCallback();

        #endregion

        #region Private Method(s)

        /// <summary>
        /// This method handles notifying the user if an update to the product is available.
        /// </summary>
        private void NotifyUser(Boolean displayUI)
        {
            if (IsUpdateAvailable)
            {
                String message = null;

                // Hijacking Fiddler's form because it's nice :)
                if (LatestVersionEngine.CompareTo(CurrentVersionEngine) > 0)
                {
                    message = String.Format("Version {0} of the Watcher Engine is available.\r\n{1}", LatestVersionEngine, LatestVersionReleaseNotes);
                }

                Fiddler.frmAlert alert = new Fiddler.frmAlert("Update(s) Available", message, "Would you like to download them now?", MessageBoxButtons.YesNo, MessageBoxDefaultButton.Button1);
                alert.StartPosition = FormStartPosition.CenterScreen;
                alert.ShowDialog();
                if (alert.DialogResult == DialogResult.Yes)
                {
                    Fiddler.Utilities.LaunchHyperlink("http://websecuritytool.codeplex.com/Release/ProjectReleases.aspx");
                }
            }
            else if (displayUI)
            {
                MessageBox.Show("There are no new updates to Watcher available.", "Software Update", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        /// <summary>
        /// This method attempts to contact the product site to determine the latest available 
        /// version of the product and associated release notes.  If successful, the metadata
        /// is stored for retrieval by the caller; otherwise the metadata is reset.
        /// </summary>
        private void GetLatestVersionMetadata()
        {
            Trace.TraceInformation("Checking for updates...");
            Trace.TraceInformation("Current runtime version: {0}", CurrentVersionEngine);

            HttpWebRequest Request = null;
            HttpWebResponse Response = null;

            Int32 LatestEngineMajor = -1;                     // Latest product version information...
            Int32 LatestEngineMinor = -1;
            Int32 LatestEngineBuild = -1;
            String LatestReleaseNotes = String.Empty;         // Release notes may also be available

            try
            {
                // Prepare the Engine version request
                Request = (HttpWebRequest)WebRequest.Create("http://www.casabasecurity.com/products/watcher.php");
                Request.KeepAlive = false;
                Request.UserAgent = "Casaba Security Watcher " + CurrentVersionEngine.ToString();

                // Request the current product version from the server
                Response = (HttpWebResponse)Request.GetResponse();
                if (Response.StatusCode == HttpStatusCode.OK)
                {
                    // Read the current product version from the server
                    StreamReader stream = new StreamReader(Response.GetResponseStream(), Encoding.UTF8);
                    LatestEngineMajor = Int32.Parse(stream.ReadLine());
                    LatestEngineMinor = Int32.Parse(stream.ReadLine());
                    LatestEngineBuild = Int32.Parse(stream.ReadLine());
                    LatestReleaseNotes = stream.ReadToEnd().Trim();
                }
                else
                {
                    // The document containing the version information doesn't seem to exist, or was otherwise unexpected
                    Trace.TraceWarning("Warning: Connection succeeded, but response code {0} unexpected.", Response.StatusCode);
                    MessageBox.Show("Unexpected response while checking for Engine version update.", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            }

            catch (WebException e)
            {
                // Thrown if there is an error during the web request
                Trace.TraceError("Error: WebException: {0}", e.Message);
                MessageBox.Show(e.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }

            catch (ProtocolViolationException e)
            {
                // Thrown if there is an error during the generic network request
                Trace.TraceError("Error: ProtocolViolationException: {0}", e.Message);
                MessageBox.Show(e.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }

            catch (IOException e)
            {
                // Thrown on any stream error
                Trace.TraceError("Error: IOException: {0}", e.Message);
                MessageBox.Show(e.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }

            catch (FormatException e)
            {
                // Thrown when the version number parsing fails
                Trace.TraceError("Error: FormatException: {0}", e.Message);
                MessageBox.Show(e.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }

            finally
            {
                if (Response != null) Response.Close();
            }

            // If the build number has not been set, an error occurred; set the latest version to null.
            // Otherwise, create an instance of the latest available version information.
            // Version numbers are integers greater than or equal to zero (http://msdn.microsoft.com/en-us/library/system.version.aspx)
            if (LatestEngineBuild == -1)
            {
                Trace.TraceWarning("Unable to retrieve latest engine version information.");
                LatestVersionEngine = new Version();
                LatestVersionReleaseNotes = String.Empty;
            }
            else
            {
                LatestVersionEngine = new Version(LatestEngineMajor, LatestEngineMinor, LatestEngineBuild);
                LatestVersionReleaseNotes = LatestReleaseNotes;
                Trace.TraceInformation("Latest available Engine version: {0}", LatestVersionEngine);
            }
        }

        #endregion

        #region Public Method(s)

        /// <summary>
        /// Contact the product web site, determine if a newer version of the product is available and notify the user.
        /// </summary>
        /// <remarks>
        /// TODO: It would be ideal to do all of the I/O asynchronously and not tie up a thread.
        /// TODO: Disable the Check For Updates button while the update check is in progress; enable again once finished.
        /// TODO: Display the notification in front of the UI
        /// </remarks>
        public void CheckForUpdate()
        {
            CheckForUpdate(true);
        }

        /// <summary>
        /// Contact the product web site, determine if a newer version of the product is available and notify the user.
        /// </summary>
        /// <remarks>
        /// TODO: It would be ideal to do all of the I/O asynchronously and not tie up a thread.
        /// TODO: Disable the Check For Updates button while the update check is in progress; enable again once finished.
        /// TODO: Display the notification in front of the UI
        /// </remarks>
        public void CheckForUpdate(Boolean displayUI)
        {
            // Use a delegate to perform the operation asynchronously--since we're doing network IO,
            // this wastes a thread for the sake of simplicity.
            GetLatestVersionMetadataCallback callback = GetLatestVersionMetadata;

            // Invoke the update check asynchronously
            callback.BeginInvoke(

                // This is the callback method
                delegate(IAsyncResult ar)
                {
                    // Tidy up after the update check
                    GetLatestVersionMetadataCallback _callback = (GetLatestVersionMetadataCallback)ar.AsyncState;
                    _callback.EndInvoke(ar); // TODO: this will throw any exceptions that happened during the call

                    // Inform the user of any available updates
                    NotifyUser(displayUI);
                },

                // This is the AsyncState seen in the callback method above
                callback);
        }

        #endregion
    }
}