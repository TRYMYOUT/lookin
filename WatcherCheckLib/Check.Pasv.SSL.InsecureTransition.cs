// WATCHER
//
// Check.Pasv.SSL.InsecureTransition.cs
// Checks Referrer header for SSL pages that load insecure HTTP content.
//
// Copyright (c) 2009 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using Fiddler;

namespace CasabaSecurity.Web.Watcher.Checks
{
    public class CheckPasvSSLInsecureTransition : WatcherCheck
    {
        private int findingnum;

        public override String GetName()
        {
            return "SSL - Look for insecure transition from HTTPS to HTTP in Referer header.";
        }

        public override String GetDescription()
        {
            String desc = "This check looks for insecure transitions between HTTPS and HTTP.  The issue is that " +
                "a secure HTTPS page might be loading resources from insecure HTTP pages.";

            return desc;
        }

        private void AddAlert(Session session, String header)
        {
            String name = "HTTPS/HTTP Insecure Transition Referer Header";
            findingnum++;
            String text =
                name +
                "\r\n\r\n" +
                "Risk: Medium\r\n\r\n" +
                "An HTTPS to HTTP transition appears to have occurred when requesting the following URL:\r\n\r\n" +
                session.url +
                "\r\n\r\n" + findingnum.ToString() + ") " +
                "The referrer header returned was:\r\n\r\n" +
                header;

            WatcherEngine.Results.Add(WatcherResultSeverity.Medium, session.id, session.url, name, text, StandardsCompliance, findingnum);
        }

        public override void Check(Session session, UtilityHtmlParser htmlparser)
        {
            String header = null;
            findingnum = 0;

            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname))
            {
                if (!session.isHTTPS)
                {
                    if (session.oRequest.headers.Exists("referer"))
                    {
                        header = session.oRequest.headers["referer"];

                        if (header.Trim().ToLower().IndexOf("https://") == 0)
                            AddAlert(session, header);
                    }
                }
            }
        }
    }
}