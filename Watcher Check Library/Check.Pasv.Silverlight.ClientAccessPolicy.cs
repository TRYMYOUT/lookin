// WATCHER
//
// Check.Pasv.Silverlight.ClientAccessPolicy.cs
// Checks for insecure access through Silverlight's policy file.
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
    // TODO: research more to do with this check - see:
    //  http://msdn.microsoft.com/en-us/library/cc645032(VS.95).aspx
    public class CheckPasvSilverlightClientAccessPolicy : WatcherCheck
    {
        [ThreadStatic] static private string alertbody = "";
        [ThreadStatic] static private int findingnum;

        public CheckPasvSilverlightClientAccessPolicy()
        {
            // Complies with Microsoft SDL
            StandardsCompliance =
                WatcherCheckStandardsCompliance.MicrosoftSDL;

            CheckCategory = WatcherCheckCategory.Silverlight;
            LongName = "Silverlight - Search for insecure domain references in Silverlight client access policy.";
            LongDescription = "Silverlight assemblies can allow cross-domain access defined through a clientaccesspolicy.xml or crossdomain.xml. This can introduce security vulnerability when access is allowed to and from untrusted domains. For example, if a wildcard '*' is set in the access list Silverlight assemblies may introduce Cross-Site Request Forgery or other issues. The potential security issues around this are numerous depending on the functionality of the application, for more info check out the Silverlight security white paper referenced.";
            ShortName = "Silverlight clientaccesspolicy.xml insecure domain reference";
            ShortDescription = "The clientaccesspolicy.xml file found at the following URL contains a potentially insecure domain reference.  This configuration allows the Silverlight code to have cross-domain communication with third-party domains, which may lead to security vulnerabilities if the Silverlight code can be abused:\r\n\r\n";
            Reference = "http://websecuritytool.codeplex.com/wikipage?title=Checks#silverlight-client-access-policy";
            Recommendation = "Narrow the scope of a crossdomain.xml file to a small set of required hosts. Never use wildcards '*' to denote allowed domains.";

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

            // This is a check for cross-domain issues.  So if Watcher is not configured with 
            // an origin domain, treat the session response hostname as the origin.
            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname, session.hostname))
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