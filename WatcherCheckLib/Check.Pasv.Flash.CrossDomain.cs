// WATCHER
//
// Check.Pasv.Flash.CrossDomain.cs
// Checks the Flash crossdomain.xml file for insecure access.
//
// Copyright (c) 2009 Casaba Security, LLC
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
        private string alertbody = "";
        private int findingnum;

        public override String GetName()
        {
            return "Flash - Look for issues with the Flash cross-domain policy file.";
        }

        public override String GetDescription()
        {
            String desc = "Flash objects can allow cross-domain access defined through a crossdomain.xml.  This can introduce security vulnerability " +
                    "when access is allowed from untrusted domains.  For example, if a wildcard '*' is set in the access list " +
                    "Flash will allow access from any domain.  The potential security issues around this are numerous, for more info check out: \r\n\r\n" +
                    "http://jeremiahgrossman.blogspot.com/2008/05/crossdomainxml-invites-cross-site.html";

            return desc;
        }

        private void AddAlert(Session session)
        {
            String name = "Flash crossdomain.xml Insecure Domain Reference";
            String text =

                name +
                "\r\n\r\n" +
                "Risk: Medium\r\n\r\n" +
                "The crossdomain.xml file found at the following URL contains an insecure domain reference:\r\n\r\n" +
                session.url +
                "\r\n\r\n" +
                alertbody;

            WatcherEngine.Results.Add(WatcherResultSeverity.Medium, session.id, session.url, name, text, StandardsCompliance, findingnum);
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

        public override void Check(Session session, UtilityHtmlParser htmlparser)
        {
            String pat = null;
            String bod = null;
            String dom = null;
            alertbody = "";
            findingnum = 0;

            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname))
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
                                            if (!WatcherEngine.Configuration.IsOriginDomain(dom) && !WatcherEngine.Configuration.IsTrustedDomain(dom))
                                                AssembleAlert(dom, m.ToString());
                                    }

                                    foreach (Match m in Utility.GetHtmlTags(b, "allow-http-request-headers-from"))
                                    {
                                        dom = Utility.GetHtmlTagAttribute(m.ToString(), "domain");
                                        if (dom != null)
                                            if (!WatcherEngine.Configuration.IsOriginDomain(dom) && !WatcherEngine.Configuration.IsTrustedDomain(dom))
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