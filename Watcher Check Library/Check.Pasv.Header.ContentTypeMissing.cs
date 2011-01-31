// WATCHER
//
// Check.Pasv.Header.ContentTypeMissing.cs
// Checks for HTTP responses that don't set a content-type value.
//
// Copyright (c) 2010 Casaba Security, LLC
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

        public CheckPasvHeaderContentTypeMissing()
        {
            CheckCategory = WatcherCheckCategory.Header;
            LongName = "Header - Checks that a Content-Type header is included in the HTTP response and alerts when it isn't.";
            LongDescription = "This check flags HTTP responses which don't set a Content-Type value.  The HTTP Content-Type header lets a browser know what type of content to expect e.g. HTML, javascript, images, media, etc. When a Content-Type value is not specified, the browser is forced to sniff the content to determine what it might be. Forcing browsers into this state is undesirable as it can lead to exploitable conditions.";
            ShortName = "Content-Type header";
            ShortDescription = "The response to the following request did not include a Content-Type header:\r\n\r\n";
            Reference = "http://websecuritytool.codeplex.com/wikipage?title=Checks#http-cache-control-header-no-store";
            Recommendation = "Ensure each page is setting the specific and appropriate content-type value for the content being delivered.";
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
            string name = "Missing Content-Type header";
            string text =
                Reference +
                "The response to the following request did not include a Content-Type header:\r\n\r\n" +
                session.fullUrl;

            WatcherEngine.Results.Add(WatcherResultSeverity.Low, session.id, session.fullUrl, name, text, StandardsCompliance, 1, Reference);
        }

        private void AddAlert2(Session session)
        {
            string name = "Empty Content-Type header";
            string text =
                Reference +
                "The response to the following request included a blank Content-Type header:\r\n\r\n" +
                session.fullUrl;

            WatcherEngine.Results.Add(WatcherResultSeverity.Low, session.id, session.fullUrl, name, text, StandardsCompliance, 1, Reference);
        }

        public override void Check(Session session)
        {
            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname))
                if (session.responseCode == 200 || session.responseCode == 401)
                    if (session.responseBodyBytes.Length > 0)
                        if (!session.oResponse.headers.Exists("Content-Type"))
                            AddAlert(session);
                        else if (String.IsNullOrEmpty(session.oResponse.headers["Content-Type"].Trim().ToLower()))
                            AddAlert2(session);
        }
    }
}