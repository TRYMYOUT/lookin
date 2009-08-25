// WATCHER
//
// Check.Pasv.SSL.InsecureFormLoad.cs
// Checks for insecure HTTP pages that host HTTPS forms.
//
// Copyright (c) 2009 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Text;
using Fiddler;

namespace CasabaSecurity.Web.Watcher.Checks
{
    public class CheckPasvSSLInsecureFormLoad : WatcherCheck
    {
        private int findingnum;

        public override String GetName()
        {
            return "SSL - Look for insecure transition from HTTP to HTTPS during Form Post.";
        }

        public override String GetDescription()
        {
            String desc = "This check looks for insecure HTTP pages that host HTTPS forms.  The issue is that " +
                "an insecure HTTP page can easily be hijacked through MITM and the secure HTTPS form can be " +
                "replaced or spoofed.";

            return desc;
        }

        private void AddAlert(Session session, String context)
        {
            String name = "HTTP to HTTPS insecure transition in form post";
            findingnum++;
            String text =

                name +
                "\r\n\r\n" +
                "Risk: Medium\r\n\r\n" +
                "The response to the following request over HTTP included an HTTPS form tag action attribute value:\r\n\r\n" +
                session.url +
                "\r\n\r\n" +
                "The context was:\r\n\r\n" +
                context;

            WatcherEngine.Results.Add(WatcherResultSeverity.Medium, session.id, session.url, name, text, StandardsCompliance, findingnum);
        }

        public override void Check(Session session, UtilityHtmlParser htmlparser)
        {
            String bod = null;
            String act = null;
            findingnum = 0;

            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname))
            {
                if (session.responseCode == 200)
                {
                    if (!session.isHTTPS)
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
                                        if (act.Trim().ToLower().IndexOf("https://") == 0)
                                            AddAlert(session, m.ToString());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
   