// WATCHER
//
// Check.Pasv.CrossDomain.StyleSheetInclusion.cs
// Checks for CSS stylesheet references outside the origin domain.
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
    /// Check for cross-domain CSS source file references, akin to client-side mashups.
    /// </summary>
    public class CheckPasvCrossDomainStylesheetInclusion : WatcherCheck
    {
        [ThreadStatic] static private string alertbody = "";
        [ThreadStatic] static private int findingnum;

        public override String GetName()
        {
            return "Cross-Domain - Check for cross-domain CSS source file references, akin to client-side mashups.";
        }

        public override String GetDescription()
        {
            String desc = "This check tries to identify cross-domain CSS stylesheet references in the page, " +
                    "e.g. import url('nottrusted.com').  This can be an issue when untrusted CSS " +
                    "code gets introduced to the page through.\r\n\r\n";

            return desc;
        }

        private void AddAlert(Session session)
        {
            String name = "Third-party (cross-domain) style sheet import or inclusion";
            String text =
                "Risk: Medium\r\n\r\n" +
                "The page at the following URL includes one or more style sheet files from a third-party domain:\r\n\r\n" +
                session.fullUrl +
                "\r\n\r\n" +
                alertbody;

            WatcherEngine.Results.Add(WatcherResultSeverity.Medium, session.id, session.fullUrl, name, text, StandardsCompliance, findingnum);
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

        private void CheckCssImport(Session session, String body)
        {
            String uri = null;
            String dom = null;

            // supported forms:
            // @import "url"
            // @import 'url'
            // @import url("url")
            // @import url('url')

            foreach (Match m in Regex.Matches(body, "@(I|i)mport.*?(\"|\').*?(\"|\')"))
            {
                Match a = Regex.Match(m.ToString(), "(\"|\').*?(\"|\')");

                if (a.Success)
                {
                    uri = Utility.StripQuotes(a.ToString());

                    dom = Utility.GetUriDomainName(uri);
                    if (dom != null)
                        if (!WatcherEngine.Configuration.IsOriginDomain(dom, session.hostname) && !WatcherEngine.Configuration.IsTrustedDomain(dom))
                            AssembleAlert(dom, m.ToString());
                }
            }
        }

        public override void Check(Session session, UtilityHtmlParser htmlparser)
        {
            String bod = null;
            String src = null;
            String dom = null;
            String rel = null;
            String[] bods = null;
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

                            // Check each style block for import directives
                            bods = Utility.GetHtmlTagBodies(bod, "style");
                            if (bods != null)
                            {
                                foreach (String b in bods)
                                {
                                    CheckCssImport(session, b);
                                }
                            }
                            foreach (Match m in Utility.GetHtmlTags(bod, "link"))
                            {
                                rel = Utility.GetHtmlTagAttribute(m.ToString(), "rel");
                                if (rel != null)
                                {
                                    // Check is .css file for its origin
                                    if (rel == "stylesheet")
                                    {
                                        src = Utility.GetHtmlTagAttribute(m.ToString(), "href");
                                        if (src != null)
                                        {
                                            dom = Utility.GetUriDomainName(src);
                                            if (dom != null)
                                                if (!WatcherEngine.Configuration.IsOriginDomain(dom, session.hostname) && !WatcherEngine.Configuration.IsTrustedDomain(dom))
                                                    AssembleAlert(dom, m.ToString());
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if (Utility.IsResponseCss(session))
                    {
                        bod = Utility.GetResponseText(session);
                        if (bod != null)
                            CheckCssImport(session, bod);
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