// WATCHER
//
// Check.Pasv.Header.ContentTypeMissing.cs
// Checks for HTTP responses that don't set a content-type value.
//
// Copyright (c) 2009 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using Fiddler;

namespace CasabaSecurity.Web.Watcher.Checks
{
    /// <summary>
    /// Checks that a Content-Type header is included in the HTTP response and alerts when it isn't. 
    /// </summary>
    public class CheckPasvHeaderContentTypeMissing : WatcherCheck
    {
        private int findingnum;

        public override String GetName()
        {
            return "Header - Checks that a Content-Type header is included in the HTTP response and alerts when it isn't. ";
        }

        public override String GetDescription()
        {
            String desc = "This check flags HTTP responses which don't set a Content-Type value." + 
                    "The HTTP Content-Type header lets a browser know what type of content to expect e.g. HTML, " +
                    "javascript, images, media, etc.  When a Content-Type value is not specified, the browser is forced " +
                    "to sniff the content to determine what it might be.  Forcing browsers into this state is undesirable as " +
                    "it can lead to exploitable conditions.";

            return desc;
        }

        private void AddAlert(Session session)
        {
            string name = "No Content-Type header";
            findingnum++;
            string text =

                name +
                "\r\n\r\n" +
                "Risk: Low\r\n\r\n" +
                findingnum.ToString() + ") " +
                "The response to the following request did not include a Content-Type header:\r\n\r\n" +
                session.url;

            WatcherEngine.Results.Add(WatcherResultSeverity.Low, session.id, session.url, name, text, StandardsCompliance, findingnum);
        }

        private void AddAlert2(Session session)
        {
            string name = "Empty Content-Type header";
            findingnum++;
            string text =

                name +
                "\r\n\r\n" +
                "Risk: Low\r\n\r\n" +
                findingnum.ToString() + ") " +
                "The response to the following request included a blank Content-Type header:\r\n\r\n" +
                session.url;

            WatcherEngine.Results.Add(WatcherResultSeverity.Low, session.id, session.url, name, text, StandardsCompliance, findingnum);
        }

        public override void Check(Session session, UtilityHtmlParser htmlparser)
        {
            findingnum = 0;
            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname))
                if (session.responseCode == 200 || session.responseCode == 401)
                    if (!session.HTTPMethodIs("CONNECT") && session.responseBodyBytes.Length > 0)
                        if (!session.oResponse.headers.Exists("Content-Type"))
                            AddAlert(session);
                        else if (String.IsNullOrEmpty(session.oResponse.headers["Content-Type"].Trim().ToLower()))
                            AddAlert2(session);
        }
    }
}