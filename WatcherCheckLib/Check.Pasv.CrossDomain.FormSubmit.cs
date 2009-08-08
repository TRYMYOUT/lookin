// WATCHER
//
// Check.Pasv.CrossDomain.FormSubmit.cs
// Checks for forms that post outside the origin domain.
//
// Copyright (c) 2009 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Text.RegularExpressions;
using Fiddler;

namespace CasabaSecurity.Web.Watcher.Checks
{
    /// <summary>
    /// Look for cross-domain Form submission cases when <form> HTML tag "action" attribute points to
    /// an offsite domain.
    /// </summary>
    public class CheckPasvCrossDomainFormSubmit : WatcherCheck
    {
        private string alertbody = "";
        private int findingnum;

        public override String GetName()
        {
            return "Cross-Domain - Cross-domain Form submit when <form> HTML tag \"action\" attribute points to an offsite domain.";
        }

        public override String GetDescription()
        {
            String desc = "This check identifies HTML forms that post data offsite to a domain other than " +
                    "the origin domain.  This would include subdomains if you didn't specify a wildcard or " +
                    "a trusted domain in your configuration, e.g. *.lookout.net.";

            return desc;
        }

        private void AddAlert(Session session)
        {
            String name = "Third-party (Cross Domain) Form Submit";
            String text =

                name +
                "\r\n\r\n" +
                "Risk: Medium\r\n\r\n" +
                "The page at the following URL submits one or more forms to a third-party domain:\r\n\r\n" +
                session.url +
                "\r\n\r\n" +
                alertbody +
                "\r\n\r\n";

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
            String bod = null;
            String act = null;
            String dom = null;

            alertbody = "";
            findingnum = 0;

            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname))
            {
                if (session.responseCode == 200)
                {
                    if (Utility.IsResponseHtml(session))
                    {
                        bod = Utility.GetResponseText(session);
                        if (bod != null)
                        {
                            foreach (Match m in Utility.GetHtmlTags(bod, "form"))
                            {
                                act = Utility.GetHtmlTagAttribute(m.ToString(), "action");
                                if (act != null)
                                {
                                    dom = Utility.GetUriDomainName(act);
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