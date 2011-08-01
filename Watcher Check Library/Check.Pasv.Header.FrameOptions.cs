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
        public CheckPasvHeaderFrameOptions()
        {
            CheckCategory = WatcherCheckCategory.Header;
            LongName = "Header - Checks that the 'X-Frame-Options' header is being set for defense against 'ClickJacking' attacks.";
            LongDescription = "Including the X-Frame-Options header in the server HTTP response instructs the browser to prevent the web page from being displayed in a subframe of the page. That is, it's a security measure similar to 'framebusting' which prevents malicious websites from hosting your website in an iframe. This check flags HTTP responses which don't set this header.  The check  reports unique URI path's but ignores the query component.";
            ShortName = "X-Frame-Options header was not set.";
            ShortDescription = "The response to the following request did not include a X-Frame-Options header:\r\n\r\n";
            Reference = "http://websecuritytool.codeplex.com/wikipage?title=Checks#http-header-x-frame-options";
            Recommendation = "Most modern Web browsers support the X-Frame-Options HTTP header, ensure it's set on all web pages returned by your site.";
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
            string text =
                Reference +
                "The response to the following request did not include a X-Frame-Options header: \r\n\r\n" +
                url;

            WatcherEngine.Results.Add(WatcherResultSeverity.Low, session.id, url, name, text, StandardsCompliance, 1, Reference);
        }

        private void AddAlert(Session session, string value)
        {
            string name = "X-FRAME-OPTIONS header was not set properly";
            string url = session.fullUrl.Split('?')[0];
            string text =
                "The response to the following request did not set the X-Frame-Options header value to 'DENY' or 'SAMEORIGIN'. " +
                "The value set was: \r\n\r\n" + value + "\r\n\r\n";

            WatcherEngine.Results.Add(WatcherResultSeverity.Low, session.id, url, name, text, StandardsCompliance, 1, Reference);
        }

        public override void Check(Session session)
        {
            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname))
            {
                if (session.responseCode == 200 && session.responseBodyBytes.Length > 0)
                {     
                    // Only look at HTML responses...? TODO: should this consider other MIME types?
                    if (Utility.IsResponseHtml(session))
                    {
                        if (session.oResponse.headers.Exists("X-Frame-Options"))
                        {
                            string value = session.oResponse.headers["X-Frame-Options"];
                            if (!value.Equals("SAMEORIGIN", StringComparison.OrdinalIgnoreCase) &&
                                !value.Equals("DENY", StringComparison.OrdinalIgnoreCase))
                            {
                                AddAlert(session,value);
                            }
                        }
                        // The header doesn't exist
                        else
                        {
                            AddAlert(session);
                        }

                    }
                }
            }
        }
    }
}