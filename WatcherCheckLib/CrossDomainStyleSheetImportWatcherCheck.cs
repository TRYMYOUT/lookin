using System;
using System.Text.RegularExpressions;
using Fiddler;

namespace WatcherCheckLib
{
    /// <summary>
    /// Check for cross-domain CSS file imports, akin to client-side mashups.
    /// </summary>
    public class CrossDomainStyleSheetImportWatcherCheck : WatcherEngine.WatcherCheck
    {
        private string alertbody = "";

        public override String GetName()
        {
            return "Check for cross-domain CSS file imports, akin to client-side mashups.";
        }

        private void AddAlert(WatcherEngine.Watcher watcher, Session session)
        {
            String name = "Third-party (Cross Domain) Style Sheet Import";
            String text =

                name +
                "\r\n\r\n" +
                "Risk: Medium\r\n\r\n" +
                "The page at the following URL imports one or more style sheet files from a third-party domain:\r\n\r\n" +
                session.url +
                "\r\n\r\n" +
                alertbody +
                "\r\n\r\n";


            watcher.AddAlert(WatcherEngine.WatcherCheck.Medium, session.id, session.url, name, text);
        }

        private void AssembleAlert(String domain, String context)
        {
            alertbody = alertbody + "The domain referenced was: " +
                domain +
                "\r\n" +
                "The context was: " +
                context +
                "\r\n\r\n";
        }

        private void CheckCssImport(WatcherEngine.Watcher watcher, Session session, String body)
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
                        if (!watcher.IsOriginDomain(dom) && !watcher.IsTrustedDomain(dom))
                            AssembleAlert(dom, m.ToString());
                }
            }
        }

        public override void Check(WatcherEngine.Watcher watcher, Session session)
        {
            String[] bods = null;
            String body = null;
            alertbody = "";

            if (watcher.IsOriginDomain(session.hostname))
            {
                if (session.responseCode == 200)
                {
                    if (Utility.IsResponseHtml(session))
                    {
                        body = Utility.GetResponseText(session);
                        if (body != null)
                        {
                            bods = Utility.GetHtmlTagBodies(body, "style");
                            if (bods != null)
                                foreach (String b in bods)
                                    CheckCssImport(watcher, session, b);
                        }
                    }

                    if (Utility.IsResponseCss(session))
                    {
                        body = Utility.GetResponseText(session);
                        if (body != null)
                            CheckCssImport(watcher, session, body);
                    }
                }
                if (!String.IsNullOrEmpty(alertbody))
                {
                    AddAlert(watcher, session);
                }
            }
        }
    }
}