// WATCHER
//
// VersionCheck.cs
// Implements the VersionCheck class.
//
// Copyright (c) 2009 Casaba Security, LLC
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
        private Version _CurrentVersion = null;
        private Version _LatestVersion = new Version();
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
        public Version CurrentVersion
        {
            get
            {
                if (_CurrentVersion == null)
                {
                    Version AsmVersion = Assembly.GetExecutingAssembly().GetName().Version;
                    _CurrentVersion = new Version(AsmVersion.Major, AsmVersion.Minor, AsmVersion.Build);
                }
                return _CurrentVersion;
            }
        }

        /// <summary>
        /// This property determines if updates are available.
        /// </summary>
        public Boolean IsUpdateAvailable
        {
            get { return LatestVersion.CompareTo(CurrentVersion) > 0; }
        }

        /// <summary>
        /// This property returns the latest version available from the product web site.
        /// </summary>
        public Version LatestVersion
        {
            get { return _LatestVersion; }
            private set { _LatestVersion = value; }
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
        private void NotifyUser()
        {
            if (IsUpdateAvailable)
            {
                // Hijacking Fiddler's form because it's nice :)
                Fiddler.frmAlert alert = new Fiddler.frmAlert("Update Available", String.Format("Watcher version {0} is available.", LatestVersion), "Would you like to download it now?", MessageBoxButtons.YesNo, MessageBoxDefaultButton.Button1);
                alert.StartPosition = FormStartPosition.CenterScreen;
                alert.ShowDialog();
                if (alert.DialogResult == DialogResult.Yes)
                {
                    Fiddler.Utilities.LaunchHyperlink("http://websecuritytool.codeplex.com/Release/ProjectReleases.aspx");
                }
            }
            else MessageBox.Show("There are no new updates to Watcher available.", "Software Update", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        /// <summary>
        /// This method attempts to contact the product site to determine the latest available 
        /// version of the product and associated release notes.  If successful, the metadata
        /// is stored for retrieval by the caller; otherwise the metadata is reset.
        /// </summary>
        private void GetLatestVersionMetadata()
        {
            Trace.TraceInformation("Checking for updates...");
            Trace.TraceInformation("Current runtime version: {0}", CurrentVersion);

            HttpWebRequest Request = null;
            HttpWebResponse Response = null;

            Int32 LatestMajor = -1;                     // Latest product version information...
            Int32 LatestMinor = -1;
            Int32 LatestBuild = -1;
            String LatestReleaseNotes = String.Empty;   // Release notes may also be available

            try
            {
#if true
                // Prepare the version request
                Request = (HttpWebRequest)WebRequest.Create("http://www.casabasecurity.com/products/watcher.php");
                Request.KeepAlive = false;

                // Request the current product version from the server
                Response = (HttpWebResponse)Request.GetResponse();
                if (Response.StatusCode == HttpStatusCode.OK)
                {
                    // Read the current product version from the server
                    StreamReader stream = new StreamReader(Response.GetResponseStream(), Encoding.UTF8);
                    LatestMajor = Int32.Parse(stream.ReadLine());
                    LatestMinor = Int32.Parse(stream.ReadLine());
                    LatestBuild = Int32.Parse(stream.ReadLine());
                    LatestReleaseNotes = stream.ReadToEnd().Trim();
                }
                else
                {
                    // The document containing the version information doesn't seem to exist, or was otherwise unexpected
                    Trace.TraceWarning("Warning: Connection succeeded, but response code {0} unexpected.", Response.StatusCode);
                    MessageBox.Show("Unexpected response while checking for version update.", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
#else
                LatestMajor = 1;
                LatestMinor = 3;
                LatestBuild = 0;
#endif
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
            if (LatestBuild == -1)
            {
                Trace.TraceWarning("Unable to retrieve latest version information.");
                LatestVersion = new Version();
                LatestVersionReleaseNotes = String.Empty;
            }
            else
            {
                LatestVersion = new Version(LatestMajor, LatestMinor, LatestBuild);
                LatestVersionReleaseNotes = LatestReleaseNotes;
                Trace.TraceInformation("Latest available version: {0}", LatestVersion);
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
                    NotifyUser();
                },

                // This is the AsyncState seen in the callback method above
                callback);
        }

        #endregion
    }
}