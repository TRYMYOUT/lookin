using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Microsoft.TeamFoundation;
using Microsoft.TeamFoundation.Client;
using Microsoft.TeamFoundation.Common;
using Microsoft.TeamFoundation.WorkItemTracking.Client;
using CasabaSecurity.Web.Watcher.Collections;

namespace CasabaSecurity.Web.Watcher.TeamFoundation
{
    public sealed class TeamFoundationAdapter
    {
        private TeamFoundationConfiguration _configuration = new TeamFoundationConfiguration();

        /// <summary>
        /// This class is instantiated by its factory method, Create().
        /// </summary>
        private TeamFoundationAdapter()
        {
        }

        /// <summary>
        /// This class is instantiated by its factory method, Create().
        /// </summary>
        /// <param name="serverName">The server to connect to.</param>
        /// <param name="projectName">The project to connect to.</param>
        private TeamFoundationAdapter(String serverName, String projectName)
        {
            // Store our connection metadata
            ServerName = serverName;
            ProjectName = projectName;

            // Read the configuration each time Watcher findings are exported, 
            // in the event the user has updated the mappings.
            _configuration.Load();
        }

        internal String ServerName { get; private set; }
        internal String ProjectName { get; private set; }
        internal TeamFoundationServer Server { get; private set; }
        internal Project Project { get; private set; }
        internal TeamFoundationConfiguration Configuration { get { return _configuration; } }

        /// <summary>
        /// Create an instance of the Team Foundation adapter, using the specified server and project as data sinks.
        /// </summary>
        /// <param name="serverName">The server to connect to.</param>
        /// <param name="projectName">The project to connect to.</param>
        public static TeamFoundationAdapter Create(String serverName, String projectName)
        {
            return new TeamFoundationAdapter(serverName, projectName);
        }

        /// <summary>
        /// This method connects to the Team Foundation Server specified on instantiation.
        /// </summary>
        /// <remarks>
        /// Unfortunately, since the TFS credentials provider shows a message box (particularly on error)
        /// that is not bound to the UI thread, the message box may be hidden.  To resolve this, we must
        /// ensure that we are on a UI thread before using the credentials provider.
        /// </remarks>
        public void Connect()
        {
            Trace.TraceInformation("Connecting to server...");
            WatcherEngine.ProgressDialog.UpdateProgress("Connecting to server...");

            try
            {
                // Connect to the specified server using cached credentials.  If the credentials are not cached,
                // display an authentication dialog and ask for them.
                Server = TeamFoundationServerFactory.GetServer(ServerName, new UICredentialsProvider());
                Server.EnsureAuthenticated();
            }

            catch (TeamFoundationInvalidServerNameException ex)
            {
                Trace.TraceWarning("Exception: {0}", ex.Message);
                throw new WatcherException(ex.Message, ex); // TODO: MessageBox title: Invalid Server Name
            }

            catch (TeamFoundationServerUnauthorizedException ex)
            {
                Trace.TraceWarning("Exception: {0}", ex.Message);
                throw new WatcherException(ex.Message, ex); // TODO: MessageBox title: Unauthorized
            }

            WatcherEngine.ProgressDialog.UpdateProgress();

            // Ensure we've connected to the server and project
            if (Server == null || Server.HasAuthenticated == false)
            {
                Trace.TraceError("Failed to authenticate to \"{0}\" as \"{1}\".", ServerName, Server.AuthenticatedUserName);
                throw new WatcherException("Unable to authenticate to Team Foundation Server.");   // TODO: MessageBox title: Authentication Failed
            }

            Trace.TraceInformation("Authenticated to \"{0}\" as \"{1}\".", ServerName, Server.AuthenticatedUserName);
        }

        /// <summary>
        /// This method opens the project specified on instantiation.
        /// </summary>
        public void OpenProject()
        {
            WatcherEngine.ProgressDialog.UpdateProgress("Retrieving work item store...");

            // Obtain a reference to the work item store
            WorkItemStore workItemStore = Server.GetService(typeof(WorkItemStore)) as WorkItemStore;
            if (workItemStore == null)
            {
                Trace.TraceError(String.Format("Unable to open project \"{0}\".", ProjectName)); // TODO: single string
                throw new WatcherException(String.Format("Unable to open project \"{0}\".", ProjectName));   // TODO: Message box title: Project Open Failed
            }

            WatcherEngine.ProgressDialog.UpdateProgress("Retrieving project metadata...");

            // Return the work item store's project instance, if it exists
            if (workItemStore.Projects.Contains(ProjectName) == false)
            {
                Trace.TraceWarning("Failed to obtain project name \"{0}\" from work item store.", ProjectName); // TODO: single string
                throw new WatcherException(String.Format("Failed to obtain project \"{0}\" from work item store.", ProjectName));     // TODO: Message box title: Project Open Failed
            }

            Trace.TraceInformation("Found project \"{0}\".", ProjectName);
            Project = workItemStore.Projects[ProjectName];
        }
    }
}
