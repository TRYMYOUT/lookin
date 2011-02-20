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
using Majestic12;

namespace CasabaSecurity.Web.Watcher.Checks
{
    /// <summary>
    /// Check for cross-domain CSS source file references, akin to client-side mashups.
    /// </summary>
    public class CheckPasvCrossDomainStylesheetInclusion : WatcherCheck
    {
        [ThreadStatic] static private string alertbody = "";
        [ThreadStatic] static private int findingnum;

        public CheckPasvCrossDomainStylesheetInclusion()
        {
            CheckCategory = WatcherCheckCategory.CrossDomain;
            LongName = "Cross-Domain - Check for cross-domain CSS source file references, akin to client-side mashups.";
            LongDescription = "This check tries to identify cross-domain CSS stylesheet references in the page, e.g. import url('nottrusted.com/foo.css'). This can be an issue when untrusted CSS code gets introduced to the page, leading to XSS attacks, clickjacking attacks, and other exploits related to UI layout.";
            ShortName = "Third-party (cross-domain) style sheet import or inclusion";
            ShortDescription = "The page at the following URL includes one or more style sheet files from a third-party domain:\r\n\r\n";
            Reference = "http://websecuritytool.codeplex.com/wikipage?title=Checks#cross-domain-css";
            Recommendation = "Ensure CSS files are loaded from only trusted sources, and the sources can't be controlled by end users of the application.";
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

        public override void Check(Session session)
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

                        UtilityHtmlParser parser = new UtilityHtmlParser();
                        parser.Open(session);
                        parser.Parser.bKeepRawHTML = true;
                        HTMLchunk chunk;
                        while ((chunk = parser.Parser.ParseNext()) != null)
                        {
                            if (chunk.oType == HTMLchunkType.OpenTag && chunk.sTag == "style")
                            {
                                // Get the stuff between style tags
                                chunk = parser.Parser.ParseNext();
                                CheckCssImport(session, chunk.oHTML);
                            }
                            if (chunk.oType == HTMLchunkType.OpenTag && chunk.sTag == "link" && chunk.oParams.ContainsKey("rel"))
                            {
                                rel = chunk.oParams["rel"].ToString().ToLower();
                                if (rel == "stylesheet" && chunk.oParams.ContainsKey("href"))
                                {
                                    src = chunk.oParams["href"].ToString();
                                    if (!String.IsNullOrEmpty(src))
                                    {
                                        dom = Utility.GetUriDomainName(src);
                                        if (dom != null)
                                            if (!WatcherEngine.Configuration.IsOriginDomain(dom, session.hostname) && !WatcherEngine.Configuration.IsTrustedDomain(dom))
                                                AssembleAlert(dom, chunk.oHTML);
                                    }
                                }
                            }
                        }
                        // close the parser
                        parser.Close();
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