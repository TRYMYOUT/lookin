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
    public class CheckPasvHeaderFrameOptions : WatcherCheck
    {
        private int findingnum;

        public override String GetName()
        {
            return "Header - Checks that the 'X-FRAME-OPTIONS' header for IE8's ClickJacking defense is being set by the server. ";
        }

        public override String GetDescription()
        {
            //TODO: Beef this up.
            String desc = "This check is specific to Internet Explorer 8. " +
                    "It flags HTTP responses which don't set the header to protect against ClickJacking attacks.";
            return desc;
        }

        private void AddAlert(Session session)
        {
            string name = "IE8 anti-ClickJacking header was not set.";
            string url = session.url.Split('?')[0];
            findingnum++;
            string text =

                name +
                "\r\n\r\n" +
                "Risk: Informational\r\n\r\n" +
                findingnum.ToString() + ") " +
                "The response to the following request did not include a X-FRAME-OPTIONS header: \r\n\r\n" +
                url;

            WatcherEngine.Results.Add(WatcherResultSeverity.Informational, session.id, url, name, text, StandardsCompliance, findingnum);
        }

        private void AddAlert(Session session, string value)
        {
            string name = "IE8 anti-Clickjacking not set to Deny";
            string url = session.url.Split('?')[0];
            findingnum++;
            string text =

                name +
                "\r\n\r\n" +
                "Risk: Informational\r\n\r\n" +
                findingnum.ToString() + ") " +
                "The response to the following request did not set the X-FRAME-OPTIONS header value to 'deny'. " +
                "The value set was: \r\n\r\n" + value + "\r\n\r\n";

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
                        if (Utility.IsResponseHtml(session))
                        {
                            if (!session.HTTPMethodIs("CONNECT"))
                            {
                                if (!session.oResponse.headers.Exists("X-FRAME-OPTIONS"))
                                {
                                    AddAlert(session);
                                }
                                else if (!session.oResponse.headers.ExistsAndEquals("X-FRAME-OPTIONS", "deny"))
                                {
                                    AddAlert(session, session.oResponse.headers["X-FRAME-OPTIONS"].ToString().ToLower());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}