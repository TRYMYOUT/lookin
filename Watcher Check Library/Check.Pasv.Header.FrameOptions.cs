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

        public CheckPasvHeaderFrameOptions()
        {
            CheckCategory = WatcherCheckCategory.Header;
            LongName = "Header - Checks that the 'X-FRAME-OPTIONS' header is being set for defense against 'ClickJacking' attacks.";
            LongDescription = "Including the X-FRAME-OPTIONS header in the server HTTP response instructs the browser to prevent the web page from being displayed in a subframe of the page. That is, it's a security measure similar to 'framebusting' which prevents malicious websites from hosting your website in an iframe. This check flags HTTP responses which don't set this header.";
            ShortName = "X-FRAME-OPTIONS header was not set.";
            ShortDescription = "The response to the following request did not include a X-FRAME-OPTIONS header:\r\n\r\n";
            Reference = "http://websecuritytool.codeplex.com/wikipage?title=Checks#http-header-x-frame-options";
            Recommendation = "Most modern Web browsers support the X-FRAME-OPTIONS HTTP header, ensure it's set on all web pages returned by your site.";
        }

        public override String GetName()
        {
            return LongName;
        }

        public override String GetDescription()
        {
            return LongDescription;
        }

        private void AddAlert(Session session)
        {
            string name = ShortName;
            string url = session.fullUrl.Split('?')[0];
            findingnum++;
            string text =
                Reference +
                findingnum.ToString() + ") " +
                "The response to the following request did not include a X-FRAME-OPTIONS header: \r\n\r\n" +
                url;

            WatcherEngine.Results.Add(WatcherResultSeverity.Informational, session.id, url, name, text, StandardsCompliance, findingnum, Reference);
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

            WatcherEngine.Results.Add(WatcherResultSeverity.Informational, session.id, url, name, text, StandardsCompliance, findingnum, Reference);
        }

        public override void Check(Session session)
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