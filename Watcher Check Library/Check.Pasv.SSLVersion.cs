// WATCHER
//
// Check.Pasv.SSLVersion.cs
// Checks for SSL protocols that allow v2 handshakes.
//
// Copyright (c) 2010 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Diagnostics;
using System.Text.RegularExpressions;
using Fiddler;
using System.IO;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace CasabaSecurity.Web.Watcher.Checks
{
    public class CheckPasvSSLVersion : WatcherCheck
    {
        [ThreadStatic] static private string alertbody = "";
        [ThreadStatic] static private int findingnum;

        public CheckPasvSSLVersion()
        {
            CheckCategory = WatcherCheckCategory.Ssl;
            LongName = "SSL - SSLv2 protocol check.";
            LongDescription = "When an SSL connection is initiated, this check attempts to connect to the server using the insecure SSL v2 protocol. If the server allows this, a finding is reported. Most servers today should support SSL v3 and disallow the legacy versions of SSL.";
            ShortName = "Insecure SSLv2 was allowed";
            ShortDescription = "SSL issues were identified with host:\r\n\r\n";
            Reference = "http://websecuritytool.codeplex.com/wikipage?title=Checks#ssl-v2-protocol";
            Recommendation = "Ensure that SSL version 3.0 or TLS are being forced, and SSL v2 is prohibited on the server-side application.";
        }

        public override System.Windows.Forms.Panel GetConfigPanel()
        {
            // No special configuration for this check
            return base.GetConfigPanel();
        }

        // we want to avoid doing these checks over and over for the same host
        // this list is cleared when the Clear button is clicked in the form.
        private List<String> hosts = new List<String>();

        // we only want to check the SSL handshake once per host
        private void AddAlert(Session session)
        {
            String name = ShortName;
            String text =

                "SSL issues were identified with host: \r\n" +
                session.host +		// don't change this or we'll get duplicate alerts
                "\r\n\r\n" +
                "The issue was: \r\n" +
                alertbody;

            // don't change session.host or we'll get duplicate alerts
            WatcherEngine.Results.Add(WatcherResultSeverity.High, session.id, session.fullUrl, name, text, StandardsCompliance, findingnum, Reference);
        }

        public override void Clear()
        {
            lock (hosts)
            {
                hosts = new List<String>();
            }
        }

        private void CheckSSLv2(Session session)
        {
            TcpClient client = new TcpClient(session.host, session.port);

            SslStream ssl = new SslStream(
                client.GetStream(),
                false);

            // next do SSLv2 handshake test 
            try
            {
                ssl.AuthenticateAsClient(session.host, null, SslProtocols.Ssl2, true);
            }
            catch (AuthenticationException e)
            {
                // we're letting CheckSSL() handle these instead
                // if we hit this, then the SSLv2 handshaked pass, continue to AddAlert()
                Trace.TraceWarning("Warning: Watcher check threw an unhandled exception: {0}", e.Message);
                ExceptionLogger.HandleException(e);
            }
            catch (IOException)
            {
                // The server prohibited the SSLv2 handshake, good good.
                return;
            }
            // The server allowed the insecure SSLv2 handshake, bad bad.
            findingnum++;
            alertbody = findingnum.ToString() + ") " + "The server accepts SSLv2 handshakes, which should be prohibited.\r\n";
            ssl.Flush();
            ssl.Close();
            client.Close();
        }

        public override void Check(Session session)
        {
            alertbody = "";
            findingnum = 0;

            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname))
            {
                if (session.isHTTPS)
                {
                    // don't check a host more than once
                    if (HostNotChecked(session.hostname))
                    {
                        //	CONFIG.oAcceptedServerHTTPSProtocols = SslProtocols.Ssl2;
                        CheckSSLv2(session);
                        if (!String.IsNullOrEmpty(alertbody))
                        {
                            AddAlert(session);
                        }
                    }
                }
            }
        }

        public bool HostNotChecked(String hostname)
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