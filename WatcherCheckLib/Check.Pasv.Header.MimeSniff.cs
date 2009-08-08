// WATCHER
//
// Check.Pasv.Header.MimeSniff.cs
// Checks for HTTP responses for the X-Content-Type-Options header and setting.
//
// Copyright (c) 2009 Casaba Security, LLC
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
        private int findingnum;

        public override String GetName()
        {
            return "Header - Checks to see if the 'nosniff' MIME-Sniffing defense has been specified in the response.";
        }

        public override String GetDescription()
        {
            //TODO: Beef this up.
            String desc = "This check is specific to Internet Explorer 8 and Google Chrome.  " +
                        "It flags HTTP responses which don't set the 'nosniff' header in responses. This HTTP header is used by " +
                        "certain browsers such as IE8 and Chrome to reduce the potential for vulnerability that can " +
                        "occur when an attacker can trigger and manipulate a browser's MIME-sniffing behavior. ";
            return desc;
        }

        private void AddAlert(Session session, string value)
        {
            string name = "The Anti-MIME-Sniffing header was not set to 'nosniff'.";
            string url = session.url.Split('?')[0];
            string text;
            findingnum++;
            if (String.IsNullOrEmpty(value))
            {
                text =

                    name +
                    "\r\n\r\n" +
                    "Risk: Informational\r\n\r\n" +
                    findingnum.ToString() + ") " +
                    "The response to the following request did not set the X-CONTENT-TYPE-OPTIONS header value to 'nosniff'.  " +
                    "The header was missing or the value was empty.";
            }
            else
            {
                text =

                    name +
                    "\r\n\r\n" +
                    "Risk: Informational\r\n\r\n" +
                    findingnum.ToString() + ") " +
                    "The response to the following request did not set the X-CONTENT-TYPE-OPTIONS header value to 'nosniff'.  " +
                    "The value was set to:\r\n\r\n '" + value + "'\r\n\r\n";
            }

            WatcherEngine.Results.Add(WatcherResultSeverity.Informational, session.id, url, name, text, StandardsCompliance, findingnum);
        }

        public override void Check(Session session, UtilityHtmlParser htmlparser)
        {
            findingnum = 0;
            // The 'nosniff' header is supported by IE8 and Chrome currently.
            if (session.oRequest.headers.ExistsAndContains("User-Agent", "MSIE 8.0") || session.oRequest.headers.ExistsAndContains("User-Agent", "Chrome"))
            {
                if (WatcherEngine.Configuration.IsOriginDomain(session.hostname))
                {
                    if (session.responseCode == 200)
                    {
                        // If Content-Type header doesn't exist, or if it's null/empty, or if it's text/plain
                        if (!session.oResponse.headers.Exists("Content-Type") || String.IsNullOrEmpty(session.oResponse.headers["Content-Type"].Trim().ToLower()) || Utility.IsResponsePlain(session) )
                        {
                            if (!session.HTTPMethodIs("CONNECT"))
                            {
                                if (!session.oResponse.headers.ExistsAndEquals("X-CONTENT-TYPE-OPTIONS", "nosniff"))
                                {
                                    AddAlert(session, session.oResponse.headers["X-CONTENT-TYPE-OPTIONS"].ToString().ToLower());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}