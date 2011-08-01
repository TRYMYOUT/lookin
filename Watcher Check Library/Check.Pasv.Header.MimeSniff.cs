// WATCHER
//
// Check.Pasv.Header.MimeSniff.cs
// Checks for HTTP responses for the X-Content-Type-Options header and setting.
//
// Copyright (c) 2010 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using Fiddler;

namespace CasabaSecurity.Web.Watcher.Checks
{
    /// <summary>
    /// Checks that the X-CONTENT-TYPE-OPTIONS header is set. 
    /// </summary>
    public class CheckPasvHeaderMimeSniff : WatcherCheck
    {
        [ThreadStatic] static private int findingnum;

        public CheckPasvHeaderMimeSniff()
        {
            CheckCategory = WatcherCheckCategory.Header;
            LongName = "Header - Checks that the X-CONTENT-TYPE-OPTIONS defense against MIME-sniffing has been declared.";
            LongDescription = "This check is specific to Internet Explorer 8 and Google Chrome. It flags HTTP responses which don't set the X-CONTENT-TYPE-OPTIONS header in responses. This 'nosniff' HTTP header is used by certain browsers such as IE8 and Chrome to reduce the potential for vulnerability that can occur when an attacker can trigger and manipulate a browser's MIME-sniffing behavior.";
            ShortName = "The Anti-MIME-Sniffing header was not set to 'nosniff'";
            ShortDescription = "The response to the following request did not set the X-CONTENT-TYPE-OPTIONS header value to 'nosniff'.\r\n\r\n";
            Reference = "http://websecuritytool.codeplex.com/wikipage?title=Checks#http-header-x-content-type-options";
            Recommendation = "Ensure each page sets a Content-Type header and the X-CONTENT-TYPE-OPTIONS if the Content-Type header is unknown.";
        }

        private void AddAlert(Session session, string value)
        {
            string name = "The Anti-MIME-Sniffing header was not set to 'nosniff'.";
            string url = session.fullUrl.Split('?')[0];
            string text;
            findingnum++;
            if (String.IsNullOrEmpty(value))
            {
                text =
                    findingnum.ToString() + ") " +
                    "The response to the following request did not set the X-Content-Type-Options header value to 'nosniff'.  " +
                    "The header was missing or the value was empty.";
            }
            else
            {
                text =
                    findingnum.ToString() + ") " +
                    "The response to the following request did not set the X-Content-Type-Options header value to 'nosniff'.  " +
                    "The value was set to:\r\n\r\n '" + value + "'\r\n\r\n";
            }

            WatcherEngine.Results.Add(WatcherResultSeverity.Low, session.id, session.fullUrl, name, text, StandardsCompliance, findingnum, Reference);
        }

        public override void Check(Session session)
        {
            findingnum = 0;
            // The 'nosniff' header is in Internet draft
            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname))
            {
                if (session.responseCode == 200 && session.responseBodyBytes.Length > 0)
                {
                    // If Content-Type header doesn't exist, or if it's null/empty, or if it's text/plain, to reduce noise
                    if (!session.oResponse.headers.Exists("Content-Type") || String.IsNullOrEmpty(session.oResponse.headers["Content-Type"].Trim().ToLower()) || Utility.IsResponsePlain(session) )
                    {
                        if (!session.oResponse.headers.ExistsAndEquals("X-Content-Type-Options", "nosniff"))
                        {
                            AddAlert(session, session.oResponse.headers["X-Content-Type-Options"].ToString());
                        }
                    }
                }
            }
        }
    }
}