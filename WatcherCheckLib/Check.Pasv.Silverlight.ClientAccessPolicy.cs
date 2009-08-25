// WATCHER
//
// Check.Pasv.Silverlight.ClientAccessPolicy.cs
// Checks for insecure access through Silverlight's policy file.
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
    // TODO: research more to do with this check - see:
    //  http://msdn.microsoft.com/en-us/library/cc645032(VS.95).aspx
    public class CheckPasvSilverlightClientAccessPolicy : WatcherCheck
    {
        private string alertbody;
        private int findingnum;

        public override String GetName()
        {
            return "Silverlight - Search for insecure domain references in Silverlight client access policy.";
        }

        public override String GetDescription()
        {
            String desc = "Silverlight assemblies can allow cross-domain access defined through a clientaccesspolicy.xml or crossdomain.xml." +
                    "This can introduce security vulnerability when access is allowed to and from untrusted domains.  " +
                    "For example, if a wildcard '*' is set in the access list Silverlight assemblies may introduce " +
                    "Cross-Site Request Forgery or other issues.  " +
                    "The potential security issues around this are numerous depending on the functionality of the application, " +
                    "for more info check out: \r\n\r\n" +
                    "http://msdn.microsoft.com/en-us/library/cc838250(VS.95).aspx";

            return desc;
        }

        private void AddAlert(Session session)
        {
            String name = "Silverlight clientaccesspolicy.xml insecure domain reference";
            String text =

                name +
                "\r\n\r\n" +
                "Risk: Medium\r\n\r\n" +
                "The clientaccesspolicy.xml file found at the following URL contains an insecure domain reference:\r\n\r\n" +
                session.url +
                "\r\n\r\n" +
                alertbody;

            WatcherEngine.Results.Add(WatcherResultSeverity.Medium, session.id, session.url, name, text, StandardsCompliance, findingnum);
        }

        private void AssembleAlert(String domain, String context)
        {
            findingnum++;
            alertbody = alertbody + findingnum.ToString() + ") " +
            "The domain referenced was:\r\n\r\n" +
                "\"" +
                domain +
                "\"" +
                "\r\n\r\n" +
                "The context was:\r\n\r\n" +
                context;
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

                        if (pat != null && pat.ToLower() == "clientaccesspolicy.xml")
                        {
                            bod = Utility.GetResponseText(session);
                            if (bod != null)
                            {
                                foreach (String b in Utility.GetHtmlTagBodies(bod, "allow-from"))
                                {
                                    foreach (Match m in Utility.GetHtmlTags(bod, "domain"))
                                    {
                                        dom = Utility.GetHtmlTagAttribute(m.ToString(), "uri");
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