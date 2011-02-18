// WATCHER
//
// Check.Pasv.Flash.CrossDomain.cs
// Checks the Flash crossdomain.xml file for insecure access.
//
// Copyright (c) 2010 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.IO;
using System.Text.RegularExpressions;
using Fiddler;

namespace CasabaSecurity.Web.Watcher.Checks
{
    /// <summary>
    /// Look for issues with the Flash cross-domain policy file. In particular identify when "allow-access-from" 
    /// and "allow-http-request-headers-from" are including liberal wildcards or non-origin domains.
    /// </summary>
    public class CheckPasvFlashCrossDomain : WatcherCheck
    {
        [ThreadStatic] static private string alertbody = "";
        [ThreadStatic] static private int findingnum;

        public CheckPasvFlashCrossDomain()
        {
            // Complies with Microsoft SDL
            StandardsCompliance =
                WatcherCheckStandardsCompliance.MicrosoftSdl;

            CheckCategory = WatcherCheckCategory.Flash;
            LongName = "Flash - Look for issues with the Flash cross-domain policy file.";
            LongDescription = "Flash objects can allow cross-domain access defined through a crossdomain.xml. This can introduce security vulnerability when access is allowed from untrusted domains. For example, if a wildcard '*' is set in the access list Flash will allow access from any domain. ";
            ShortName = "Flash crossdomain.xml insecure domain reference";
            ShortDescription = "The crossdomain.xml file found at the following URL contains an insecure domain reference:\r\n\r\n";
            Reference = "http://websecuritytool.codeplex.com/wikipage?title=Checks#flash-cross-domain-xml";
            Recommendation = "Narrow the scope of a crossdomain.xml file to a small set of required hosts. Never use wildcards '*' to denote allowed domains.";
        }

        public override String GetName()
        {
            return LongName;
        }

        public override String GetDescription()
        {
            return LongDescription;
        }

        private void AddAlert(Session session)
        {
            String name = ShortName;
            String text =
                ShortDescription +
                session.fullUrl +
                "\r\n\r\n" +
                alertbody;

            WatcherEngine.Results.Add(WatcherResultSeverity.High, session.id, session.fullUrl, name, text, StandardsCompliance, findingnum, Reference);
        }

        private void AssembleAlert(String domain, String context)
        {
            findingnum++;
            alertbody = alertbody + findingnum.ToString() + ") The domain referenced was: " +
                 domain +
                 "\r\n" +
                 "The context was: " +
                 context +
                 "\r\n\r\n";
        }

        public override void Check(Session session)
        {
            String pat = null;
            String bod = null;
            String dom = null;
            alertbody = "";
            findingnum = 0;

            // This is a check for cross-domain issues.  So if Watcher is not configured with 
            // an origin domain, treat the session response hostname as the origin.
            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname, session.hostname))
            {
                if (session.responseCode == 200)
                {
                    if (Utility.IsResponseXml(session) || Utility.IsResponsePlain(session))
                    {
                        pat = Path.GetFileName(session.PathAndQuery);

                        if (pat != null && pat.ToLower() == "crossdomain.xml")
                        {
                            bod = Utility.GetResponseText(session);
                            if (bod != null)
                            {
                                foreach (String b in Utility.GetHtmlTagBodies(bod, "cross-domain-policy"))
                                {
                                    foreach (Match m in Utility.GetHtmlTags(b, "allow-access-from"))
                                    {
                                        dom = Utility.GetHtmlTagAttribute(m.ToString(), "domain");
                                        if (dom != null)
                                            if (!WatcherEngine.Configuration.IsOriginDomain(dom, session.hostname) && !WatcherEngine.Configuration.IsTrustedDomain(dom))
                                                AssembleAlert(dom, m.ToString());
                                    }

                                    foreach (Match m in Utility.GetHtmlTags(b, "allow-http-request-headers-from"))
                                    {
                                        dom = Utility.GetHtmlTagAttribute(m.ToString(), "domain");
                                        if (dom != null)
                                            if (!WatcherEngine.Configuration.IsOriginDomain(dom, session.hostname) && !WatcherEngine.Configuration.IsTrustedDomain(dom))
                                                AssembleAlert(dom, m.ToString());
                                    }
                                }
                                if (!String.IsNullOrEmpty(alertbody))
                                {
                                    AddAlert(session);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}