// WATCHER
//
// Check.Pasv.SSL.CertValidation.cs
// Checks SSL certs for validation errors.
//
// Copyright (c) 2010 Casaba Security, LLC
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
    public struct SSLstate
    {
        public SslStream ssl;
        public TcpClient client;
        public Session session;

        public SSLstate(SslStream i, TcpClient g, Session s)
        {
            ssl = i;
            client = g;
            session = s;
        }
    }

    public class CheckPasvSSLCertValidation : WatcherCheck
    {
        [ThreadStatic] static private int findingnum;
        private EnableCheckConfigPanel configpanel;
        private static bool filteroff = true;
        // error string for capturing SSL validation errors
        [ThreadStatic] private string error;
        // we want to avoid doing these checks over and over for the same host
        // this list is cleared when the Clear button is clicked in the form.
        static private List<String> hosts = new List<String>();

        public CheckPasvSSLCertValidation()
        {
            // Complies with OWASP ASVL 1 & 2 (DVR 10.5 & 10.6)
            StandardsCompliance = 
                WatcherCheckStandardsCompliance.OwaspAppSecVerificationLevel1 | 
                WatcherCheckStandardsCompliance.OwaspAppSecVerificationLevel2;

            configpanel = new EnableCheckConfigPanel(this, "SSL CRL Validation", "Enable full CRL validation of SSL Certificate Chains");
            configpanel.Init();

            CheckCategory = WatcherCheckCategory.Ssl;
            LongName = "SSL - Look for certificate validation issues.";
            LongDescription = "This check validates SSL certificates and reports a finding when validation errors such as host name mis-match and expiration are found. If configured, this check will also attempt to walk the certificate chain and perform CRL revocation checking.";
            ShortName = "SSL - SSL certificate validation";
            ShortDescription = "SSL issues were identified with host:\r\n\r\n";
            Reference = "http://websecuritytool.codeplex.com/wikipage?title=Checks#ssl-certificate-validation";
            Recommendation = "Websites should use SSL certificates that match their selected hostnames, and should be re-provisioned prior to expiration.";
        }

        public override System.Windows.Forms.Panel GetConfigPanel()
        {
            System.Windows.Forms.Panel panel = new System.Windows.Forms.Panel();
            panel.Dock = System.Windows.Forms.DockStyle.Fill;
            configpanel.Dock = System.Windows.Forms.DockStyle.Fill;
            panel.Controls.Add(configpanel);
            return panel;
        }

        private void AddAlert(Session session, String context)
        {
            String name = ShortName;
            String text =

                ShortDescription +
                session.host +		// don't change this or we'll get duplicate alerts
                "\r\n\r\n" +
                context;

            // don't change session.host or we'll get duplicate alerts
            WatcherEngine.Results.Add(WatcherResultSeverity.High, session.id, session.host, name, text, StandardsCompliance, 1, Reference);
        }

        public override void Clear()
        {
            lock (hosts)
            {
                hosts = new List<String>();
            }
        }

        // The following method is invoked by the RemoteCertificateValidationDelegate.
        public static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            string error = "";
            int numfindings = 0;

            if (sslPolicyErrors.ToString().Contains("RemoteCertificateNameMismatch"))
            {
                numfindings++;
                error = error + numfindings.ToString() + ") There was a naming mismatch between the host connected to and its SSL certificate.\r\n\r\n\r\n";
            }
            if (sslPolicyErrors.ToString().Contains("RemoteCertificateChainErrors"))
            {
                error = error + "One or more errors were also found while validating the certificate chain for the server's SSL certificate.\r\n\r\n";
            }
            if (filteroff)
            {
                X509Chain certChain = chain;

                // build the cert chain from the remote cert
                certChain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
                // this is a security auditing tool, check the whole chain
                certChain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
                certChain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllFlags;
                certChain.ChainPolicy.VerificationTime = DateTime.Now;
                // allow up to a minute for this
                certChain.ChainPolicy.UrlRetrievalTimeout = new TimeSpan(0, 0, 30);

                try
                {
                    certChain.Build(new X509Certificate2(certificate));
                }
                catch (AuthenticationException)
                {
                    //ignore here, handled in the other check
                }
                foreach (X509ChainElement element in chain.ChainElements)
                {
                    if (certChain.ChainStatus.Length > 1)
                    {
                        error = error + "Certificate issuer name: " + element.Certificate.Issuer + "\r\n";
                        error = error + "Certificate valid until: " + element.Certificate.NotAfter.ToString() + "\r\n";
                        error = error + "Certificate is valid: " + element.Certificate.Verify().ToString() + "\r\n\r\n";
                        for (int index = 0; index < element.ChainElementStatus.Length; index++)
                        {
                            numfindings++;
                            error = error + numfindings.ToString() + ") " + element.ChainElementStatus[index].Status.ToString() + "\r\n\r\n";
                            error = error + element.ChainElementStatus[index].StatusInformation + "\r\n\r\n";
                        }
                    }
                }
            }
            throw new AuthenticationException(error);
                // Do not allow this client to communicate with unauthenticated servers.
        }

        private void DoCertValidation(IAsyncResult result)
        {
            SSLstate state = (SSLstate) result.AsyncState;
            string error = "";
            try
            {
                state.ssl.EndAuthenticateAsClient(result);
            }
            catch (AuthenticationException e)
            {
                if (!String.IsNullOrEmpty(e.Message))
                {
                    error = e.Message;
                    AddAlert(state.session, error);
                }
            }
            finally
            {
                state.ssl.Flush();
                state.ssl.Close();
                state.client.Close();
            }
        }

        private void CheckSSLCertificate(Session session)
        {
            TcpClient client = new TcpClient(session.host, session.port);
            SslStream ssl = new SslStream(
            client.GetStream(),
            false,
            new RemoteCertificateValidationCallback(ValidateServerCertificate),
            null);

            AsyncCallback callBack = new AsyncCallback(DoCertValidation);
            SSLstate state = new SSLstate(ssl, client, session);

            // first do cert validation checks for SSLv3 and TLS
            try
            {
                ssl.BeginAuthenticateAsClient(session.host, null, SslProtocols.Default, true, callBack, state);
            }
            catch (AuthenticationException e)
            {
                if (e.InnerException != null)
                {
                   error = e.InnerException.Message;
                }

                AddAlert(session, error);
            }

            catch (IOException)
            {
                // Something went wrong.
                return;
            }

        }
        
        public override void Check(Session session)
        {
            error = "";
            findingnum = 0;
            filteroff = configpanel.enablefiltercheckBox.Checked;
        
            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname))
            {
                if (session.isHTTPS)
                {
                    // don't check a host more than once
                    if (HostNotChecked(session.hostname))
                    {
                        CheckSSLCertificate(session);
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