// WATCHER
//
// Check.Pasv.Header.Security.cs
// Checks for HTTP responses for the X-FRAME-OPTIONS header and setting.
//
// Copyright (c) 2009 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using Fiddler;

namespace CasabaSecurity.Web.Watcher.Checks
{
    /// <summary>
    /// Checks that X-FRAME-OPTIONS header is set. 
    /// TODO: Add someway of checking for a frame breaker script?
    /// </summary>
    public class CheckPasvHeaderXssProtection : WatcherCheck
    {
        private int findingnum;

        public override String GetName()
        {
            return "Header - Checks that IE8's XSS protection filter has not been disabled by a Web-application. ";
        }

        public override String GetDescription()
        {
            //TODO: Beef this up.
            String desc = "This check is specific to Internet Explorer 8. " +
                    "It flags when an HTTP response " +
                    "sets the 'X-XSS-Protection' header to a value of 0, which disables IE8's XSS protection.";
            return desc;
        }

        private void AddAlert(Session session)
        {
            string name = "IE8 XSS protection was disabled by site";
            string url = session.url.Split('?')[0];
            findingnum++;
            string text =

                name +
                "\r\n\r\n" +
                "Risk: Informational\r\n\r\n" +
                findingnum.ToString() + ") " +
                "The response to the following request disabled IE8's XSS protection filter:\r\n\r\n " +
                url +
                "\r\n\r\n";

            WatcherEngine.Results.Add(WatcherResultSeverity.Informational, session.id, url, name, text, StandardsCompliance, findingnum);
        }

        public override void Check(Session session, UtilityHtmlParser htmlparser)
        {
            findingnum = 0;
            if (session.oRequest.headers.ExistsAndContains("User-Agent", "MSIE 8.0"))
            {
                if (WatcherEngine.Configuration.IsOriginDomain(session.hostname))
                {
                    if (session.responseCode == 200)
                    {
                        // Only look at HTML responses.
                        if (Utility.IsResponseHtml(session) || Utility.IsResponsePlain(session))
                        {
                            if (!session.HTTPMethodIs("CONNECT"))
                            {
                                if (session.oResponse.headers.ExistsAndEquals("X-XSS-Protection", "0"))
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