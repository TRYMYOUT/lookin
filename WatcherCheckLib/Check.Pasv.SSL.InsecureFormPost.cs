// WATCHER
//
// Check.Pasv.SSL.InsecureFormPost.cs
// Checks HTTPS pages that host HTTP forms.
//
// Copyright (c) 2009 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Text.RegularExpressions;
using Fiddler;

namespace CasabaSecurity.Web.Watcher.Checks
{
    public class CheckPasvSSLInsecureFormPost : WatcherCheck
    {
        private string alertbody;
        private int findingnum;

        public override String GetName()
        {
            return "SSL - Look for insecure transition from HTTPS to HTTP during Form Post.";
        }

        public override String GetDescription()
        {
            String desc = "This check looks for secure HTTPS pages that host insecure HTTP forms.  The issue is that " +
                "a secure page is transitioning to an insecure page when data is uploaded through a form. " +
                "If the data is sensitive then an issue exists.";

            return desc;
        }

        private void AddAlert(Session session)
        {
            String name = "HTTPS/HTTP Insecure Transition HTTP Form Post";
            String text =
                name +
                "\r\n\r\n" +
                "Risk: Medium\r\n\r\n" +
                "The response to the following request over HTTPS included an HTTP form tag action attribute value:\r\n\r\n" +
                session.url +
                "\r\n\r\n" + 
                alertbody;

            WatcherEngine.Results.Add(WatcherResultSeverity.Medium, session.id, session.url, name, text, StandardsCompliance, findingnum);
        }

        private void AssembleAlert(String context)
        {
            findingnum++;
            alertbody = alertbody + 
                findingnum.ToString() + ") " +
                "The context was:\r\n\r\n" +
                context;
        }

        public override void Check(Session session, UtilityHtmlParser htmlparser)
        {
            String bod = null;
            String act = null;
            alertbody = "";
            findingnum = 0;

            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname))
            {
                if (session.responseCode == 200)
                {
                    if (session.isHTTPS)
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
                                        if (act.Trim().ToLower().IndexOf("http://") == 0)
                                            AssembleAlert(m.ToString());
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