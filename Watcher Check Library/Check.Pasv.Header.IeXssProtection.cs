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
    public class CheckPasvHeaderXssProtection : WatcherCheck
    {

        public CheckPasvHeaderXssProtection()
        {
            CheckCategory = WatcherCheckCategory.Header;
            LongName = "Header - Checks that IE8's XSS protection filter has not been disabled by the Web-application.";
            LongDescription = "This check is specific to Internet Explorer 8. It flags when an HTTP response sets the X-XSS-Protection'; header to a value of 0, which disables IE8's XSS protection filter.";
            ShortName = "IE8 XSS protection was disabled by site";
            ShortDescription = "The response to the following request disabled IE8's XSS protection filter:\r\n\r\n";
            Reference = "http://websecuritytool.codeplex.com/wikipage?title=Checks#internet-explorer-xss-filter-disabled";
            Recommendation = "If IE's XSS filter must be disabled for functional or other reasons, ensure that every page of the website is properly sanitizing user input and output, and well-protected against XSS vulnerability.";
        }

        private void AddAlert(Session session)
        {
            string name = ShortName;
            string url = session.fullUrl.Split('?')[0];
            string text =
                ShortDescription +
                url +
                "\r\n\r\n";

            WatcherEngine.Results.Add(WatcherResultSeverity.Informational, session.id, session.fullUrl, name, text, StandardsCompliance, 1, Reference);
        }

        public override void Check(Session session, UtilityHtmlDocument htmlparser)
        {
            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname))
            {
                if (session.responseCode == 200 && session.responseBodyBytes.Length > 0)
                {
                    // Only look at HTML responses.
                    if (Utility.IsResponseHtml(session) || Utility.IsResponsePlain(session))
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