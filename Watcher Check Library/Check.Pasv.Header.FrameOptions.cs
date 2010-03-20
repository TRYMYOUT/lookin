// WATCHER
//
// Check.Pasv.Header.Security.cs
// Checks for HTTP responses for the X-FRAME-OPTIONS header and setting.
//
// Copyright (c) 2010 Casaba Security, LLC
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
        [ThreadStatic] static private int findingnum;

        public override String GetName()
        {
            return "Header - Checks that the 'X-FRAME-OPTIONS' header is being set for defense against 'ClickJacking' attacks. ";
        }

        public override String GetDescription()
        {
            //TODO: Beef this up.
            String desc = "Including the X-FRAME-OPTIONS header in the server HTTP response instructs the browser to prevent the web page " +
                    "from being displaed in a subframe of the page.  This check flags HTTP responses which don't set this header."  +
                    "For more information see:  \r\n\r\n" +
                    "http://blogs.msdn.com/ie/archive/2009/01/27/ie8-security-part-vii-clickjacking-defenses.aspx";
            return desc;
        }

        private void AddAlert(Session session)
        {
            string name = "X-FRAME-OPTIONS header was not set.";
            string url = session.fullUrl.Split('?')[0];
            findingnum++;
            string text =
                findingnum.ToString() + ") " +
                "The response to the following request did not include a X-FRAME-OPTIONS header: \r\n\r\n" +
                url;

            WatcherEngine.Results.Add(WatcherResultSeverity.Informational, session.id, url, name, text, StandardsCompliance, findingnum);
        }

        private void AddAlert(Session session, string value)
        {
            string name = "X-FRAME-OPTIONS header was not set to 'Deny'";
            string url = session.fullUrl.Split('?')[0];
            findingnum++;
            string text =
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
                    if (session.responseCode == 200 && session.responseBodyBytes.Length > 0)
                    {     
                        // Only look at HTML responses.
                        if (Utility.IsResponseHtml(session))
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