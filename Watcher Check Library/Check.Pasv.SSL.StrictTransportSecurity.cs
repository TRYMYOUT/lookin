// WATCHER
//
// Check.Pasv.SSL.StrictTransportSecurity.cs
// Checks for the StrictTransportSecurity flag.
//
// Copyright (c) 2011 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using Fiddler;
using System.IO;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace CasabaSecurity.Web.Watcher.Checks
{


    public class CheckPasvStrictTransportSecurity : WatcherCheck
    {
        [ThreadStatic]
        private EnableCheckConfigPanel configpanel;
        private static bool filter = true;
        private int findingnum = 0;
        private string error;
        // error string for capturing SSL validation errors
        //[ThreadStatic]
        // we want to avoid doing these checks over and over for the same host
        // this list is cleared when the Clear button is clicked in the form.
        private List<String> hosts = new List<String>();

        public CheckPasvStrictTransportSecurity()
        {
            // Complies with ???
            StandardsCompliance =
                WatcherCheckStandardsCompliance.None;

            configpanel = new EnableCheckConfigPanel(this, "Strict-Transport-Security", "Enable to only check once per unique domain name.  Otherwise checks will be performed on every response from the site.");
            configpanel.Init();
            
            CheckCategory = WatcherCheckCategory.Header;
            LongName = "Strict-Transport-Security.";
            LongDescription = "Checks if an HTTPS site sets the Strict-Transport-Security HTTP header.";
            ShortName = "Strict-Transport-Security";
            ShortDescription = "The HTTPS site did not set the Strict-Transport-Security HTTP header:\r\n\r\n";
            Reference = "http://tools.ietf.org/html/draft-ietf-websec-strict-transport-sec-01";
            Recommendation = "Websites wanting strong transport encryption protection should set the Strict-Transport-Security HTTP header.";
        }

        public override System.Windows.Forms.Panel GetConfigPanel()
        {
            System.Windows.Forms.Panel panel = new System.Windows.Forms.Panel();
            panel.Dock = System.Windows.Forms.DockStyle.Fill;
            configpanel.Dock = System.Windows.Forms.DockStyle.Fill;
            panel.Controls.Add(configpanel);
            return panel;
        }

        private void AddAlert(Session session)
        {
            String name = ShortName;
            String text =

                ShortDescription +
                session.fullUrl +
                "\r\n\r\n";

            // don't change session.host or we'll get duplicate alerts
            WatcherEngine.Results.Add(WatcherResultSeverity.Low, session.id, session.fullUrl, name, text, StandardsCompliance, 1, Reference);
        }

        public override void Clear()
        {
            lock (hosts)
            {
                hosts = new List<String>();
            }
        }


        public override void Check(Session session)
        {
            error = "";
            findingnum = 0;
            string stsHeader = "";
            filter = configpanel.enablefiltercheckBox.Checked;

            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname))
            {
                if (session.isHTTPS)
                {
                    // don't check a host more than once
                    if (filter && HostNotChecked(session.hostname))
                    {
                        // Look for the header
                        DoesHeaderExist(session);
                        return;
                    }
                    else
                    {         
                        // Look for the header
                        DoesHeaderExist(session);
                        return;
                    }
                }
            }
        }

        private void DoesHeaderExist(Session session)
        {
            if (session.oResponse.headers.Exists("Strict-Transport-Security") && 
                // Should at least have the max-age attribute set, to what though?
                session.oResponse.headers["Strict-Transport-Security"].Contains("max-age"))
            {
                return;
            }
            AddAlert(session);
        }

        private bool HostNotChecked(String hostname)
        {
            // We need to reset our hosts List when a user clicks the
            // Clear() button.  This is done through Watcher.cs clear button
            // event handler.
            // 
            lock (hosts)
            {
                // host has already been checked
                if (hosts.Contains(hostname))
                {
                    return false;
                }

                // host has not been checked yet
                else
                {
                    hosts.Add(hostname);
                    return true;
                }
            }
        }
    }
}