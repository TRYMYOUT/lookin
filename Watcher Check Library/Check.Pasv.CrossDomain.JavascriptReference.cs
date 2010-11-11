// WATCHER
//
// Check.Pasv.CrossDomain.JavascriptReference.cs
// Checks for javascript references outside the origin domain.
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
    /// Check for references to untrusted domains in javascript source code.
    /// 
    /// Do this by looking for places where javascript code builds up elements and attributes to insert into the page. (e.g. src and href)
    /// Also look for occurences of window.open calling to untrusted domains.
    /// 
    /// TODO: This check is pretty weak, but will catch some stuff.  To be robust we'd need to identify all the ways
    /// javascript can create elements in HTML or otherwise form HTTP requests.  This would require implementing a proper
    /// javascript interpreter most likely.
    /// </summary>
    public class CheckPasvCrossDomainJavascriptReference : WatcherCheck
    {
        [ThreadStatic] static private string alertbody = "";
        [ThreadStatic] static private int findingnum;

        public CheckPasvCrossDomainJavascriptReference()
        {
            CheckCategory = WatcherCheckCategory.CrossDomain;
            LongName = "Cross-Domain - Check for references to untrusted domains in javascript source code.";
            LongDescription = "This check tries to identify javascript code that uses functions like createElement(tag) to programmatically add javascript src references to the DOM, and only reports when cross-domain javascript src references are made. This would be an issue when untrusted javascript code get introduced to the page.";
            ShortName = "Third-party (cross-domain) javascript reference";
            ShortDescription = "The page at the following URL contains javascript that references a third-party domain:\r\n\r\n";
            Reference = "http://websecuritytool.codeplex.com/wikipage?title=Checks#reference-to-untrusted-javascript";
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
            alertbody = alertbody + findingnum.ToString() + ") The domain referenced was: " +
                 domain +
                 "\r\n" +
                 "The context was: " +
                 context +
                 "\r\n\r\n";
        }

        private void CheckJavascriptCrossDomainReference(Session session, String dom, String context)
        {
            dom = Utility.GetUriDomainName(dom);
            if (dom != null)
                if (!WatcherEngine.Configuration.IsOriginDomain(dom, session.hostname) && !WatcherEngine.Configuration.IsTrustedDomain(dom))
                    AssembleAlert(dom, context);
        }

        private void CheckJavascriptCrossDomainReferenceProperty(Session session, String body, String property)
        {
            // *.property = "http://www.domain.com"
            foreach (Match m in Regex.Matches(body, "\\w+?\\." + property + "\\s*?=\\s*?(\'|\").*?(\'|\")", RegexOptions.Singleline))
            {
                Match a = Regex.Match(m.ToString(), "(\'|\").*?(\'|\")");

                if (a.Success)
                    CheckJavascriptCrossDomainReference(session, Utility.StripQuotes(a.ToString()), m.ToString());
            }
        }

        private void CheckJavascriptCrossDomainReferenceWindowOpen(Session session, String body)
        {
            // window.open('http://www.domain.com', ... )
            foreach (Match m in Regex.Matches(body, "window\\.open\\s*?\\(\\s*?(\'|\").*?(\'|\").*?\\)", RegexOptions.Singleline))
            {
                Match a = Regex.Match(m.ToString(), "(\'|\").*?(\'|\")");

                if (a.Success)
                    CheckJavascriptCrossDomainReference(session, Utility.StripQuotes(a.ToString()), m.ToString());
            }
        }

        public override void Check(Session session, CasabaSecurity.Web.Watcher.UtilityHtmlParser htmlparser)
        {
            String[] bods = null;
            String body = null;

            alertbody = "";
            findingnum = 0;

            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname, session.hostname))
            {
                if (session.responseCode == 200)
                {
                    if (Utility.IsResponseHtml(session))
                    {
                        body = Utility.GetResponseText(session);
                        if (body != null)
                        {
                            bods = Utility.GetHtmlTagBodies(body, "script");
                            if (bods != null)
                            {
                                foreach (String b in bods)
                                {
                                    CheckJavascriptCrossDomainReferenceProperty(session, b, "src");
                                    CheckJavascriptCrossDomainReferenceProperty(session, b, "href");
                                    CheckJavascriptCrossDomainReferenceWindowOpen(session, b);
                                }
                            }
                        }
                    }

                    if (Utility.IsResponseJavascript(session))
                    {
                        body = Utility.GetResponseText(session);
                        if (body != null)
                        {
                            CheckJavascriptCrossDomainReferenceProperty(session, body, "src");
                            CheckJavascriptCrossDomainReferenceProperty(session, body, "href");
                            CheckJavascriptCrossDomainReferenceWindowOpen(session, body);
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