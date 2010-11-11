// WATCHER
//
// Check.Pasv.CrossDomain.ScriptInclusion.cs
// Checks for script src references outside the origin domain.
//
// Copyright (c) 2010 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Text.RegularExpressions;
using Fiddler;

namespace CasabaSecurity.Web.Watcher.Checks
{
    /// <summary>
    /// Check for cross-domain javascript source file inclusion, aka client-side mashups.  For example, <script src="offsitedomain.com"></script>
    /// </summary>
    public class CheckPasvCrossDomainScriptInclusion : WatcherCheck
    {
        [ThreadStatic] static private string alertbody = "";
        [ThreadStatic] static private int findingnum;

        public CheckPasvCrossDomainScriptInclusion()
        {
            CheckCategory = WatcherCheckCategory.CrossDomain;
            LongName = "Cross-Domain - Check for cross-domain javascript source file inclusion, aka client-side mashups.";
            LongDescription = "This check tries to identify cross-domain javascript src references in the page, e.g. <script src='nottrusted.com'>. This can be an issue when untrusted javascript code gets introduced to the page.  Unfortunately, this is a typical pattern when third-party advertising and tracking code is used (e.g. Google Analytics or DoubleClick).";
            ShortName = "Third-party (cross-domain) script inclusion";
            ShortDescription = "The page at the following URL includes one or more script files from a third-party domain:\r\n\r\n";
            Reference = "http://websecuritytool.codeplex.com/wikipage?title=Checks#cross-domain-javascript";
            Recommendation = "Ensure javascript source files are loaded from only trusted sources, and the sources can't be controlled by end users of the application.";
        }


        private void AddAlert(Session session)
        {
            String name = ShortName;
            String text =
                ShortDescription +
                session.fullUrl +
                "\r\n\r\n" +
                alertbody;

            WatcherEngine.Results.Add(WatcherResultSeverity.Medium, session.id, session.fullUrl, name, text, StandardsCompliance, findingnum, Reference);
        }

        private void AssembleAlert(String domain, String context)
        {
            findingnum++;
            alertbody = alertbody + findingnum.ToString() + ") " + "The domain referenced was: " +
                domain +
                "\r\n" +
                "The context was: " +
                context +
                "\r\n\r\n";
        }

        public override void Check(Session session, UtilityHtmlParser htmlparser)
        {
            String bod = null;
            String src = null;
            String dom = null;

            alertbody = "";
            findingnum = 0;

            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname, session.hostname))
            {
                if (session.responseCode == 200 && session.responseBodyBytes.Length > 0)
                {
                    if (Utility.IsResponseHtml(session))
                    {
                        bod = Utility.GetResponseText(session);
                        if (bod != null)
                        {
                            foreach (Match m in Utility.GetHtmlTags(bod, "script"))
                            {
                                src = Utility.GetHtmlTagAttribute(m.ToString(), "src");
                                if (src != null)
                                {
                                    dom = Utility.GetUriDomainName(src);
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