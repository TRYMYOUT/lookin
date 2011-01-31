// WATCHER
//
// Check.Pasv.UserControlled.OpenRedirect.cs
// Checks for places where user-controlled URL or Form POST parameters control Location Header redirects.
//
// Copyright (c) 2010 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Collections.Specialized;
using Fiddler;

namespace CasabaSecurity.Web.Watcher.Checks
{
    public class CheckPasvUserControlledOpenRedirect : WatcherCheck
    {
        public CheckPasvUserControlledOpenRedirect()
        {
            // Complies with OWASP ASVL 1 & 2 (DVR 11.5)
            StandardsCompliance = 
                WatcherCheckStandardsCompliance.MicrosoftSDL |
                WatcherCheckStandardsCompliance.OwaspAppSecVerificationLevel1 | 
                WatcherCheckStandardsCompliance.OwaspAppSecVerificationLevel2;

            CheckCategory = WatcherCheckCategory.UserControlled;
            LongName = "User Controlled - Open redirect.";
            LongDescription = "Open redirects are one of the OWASP 2010 Top Ten vulnerabilities. This check looks at user-supplied input in query string parameters and POST data to identify where open redirects might be possible. Open redirects occur when an application allows user-supplied input (e.g. http://nottrusted.com) to control an offsite redirect. This is generally a pretty accurate way to find where 301 or 302 redirects could be exploited by spammers or phishing attacks.";
            ShortName = "User controllable location header (Open Redirect)";
            ShortDescription = "The 301 or 302 response to a request for the following URL appeared to contain user input in the location header:\r\n\r\n";
            Reference = "http://websecuritytool.codeplex.com/wikipage?title=Checks#user-controlled-redirect";
            Recommendation = "Implement safe redirect functionality that only redirects to relative URI's, or a list of trusted domains.";

        }

        private void AddAlert(Session session, String parm, String val, String context, bool ispost)
        {
            String name = ShortName;
            if (!ispost)
            { 
                String text =

                    ShortDescription +
                    session.fullUrl +
                    "\r\n\r\n" +
                    "The user input found was:\r\n\r\n" +
                    parm +
                    "=" +
                    val +
                    "\r\n\r\n" +
                    "The context was:\r\n\r\n" +
                    context;

                WatcherEngine.Results.Add(WatcherResultSeverity.High, session.id, session.fullUrl, name, text, StandardsCompliance, 1, Reference);
            }
            else
            {
                String text =

                    "An open redirect controlled by POST parameters was detected." +
                    "To test if this is a more serious issue, you should try resending that request " +
                    "as a GET, with the POST parameter included as a query string parameter." + 
                    " For example:  http://nottrusted.com/page?url=http://lookout.net.\r\n\r\n" +
                    "The 301 or 302 response to a request for the following URL appeared to contain user input in the location header:\r\n\r\n" +
                    session.fullUrl +
                    "\r\n\r\n" +
                    "The user input found was:\r\n\r\n" +
                    parm +
                    "=" +
                    val +
                    "\r\n\r\n" +
                    "The context was:\r\n\r\n" +
                    context;

                WatcherEngine.Results.Add(WatcherResultSeverity.Informational, session.id, session.fullUrl, name, text, StandardsCompliance, 1, Reference);
            }
        }

        public void CheckUserControllableLocationHeaderValue(Session session, NameValueCollection parms, String att)
        {
            String pro = null;
            String dom = null;
            String tok = null;
            String val = null;

            if (att.Length > 0)
            {
                pro = null;
                dom = null;
                tok = null;

                // if contains protocol/domain name separator
                if (att.IndexOf("://") > 0)
                {
                    // get protocol
                    pro = att.Substring(0, att.IndexOf("://"));

                    // get domain name
                    dom = att.Substring(att.IndexOf("://") + 3);

                    // remove stuff after domain name
                    if (dom.IndexOf("/") > 0)
                        dom = dom.Substring(0, dom.IndexOf("/"));
                }
                // is local path
                else
                {
                    // get up to first slash
                    if (att.IndexOf("/") > 0)
                        tok = att.Substring(0, att.IndexOf("/"));
                    else
                        tok = att;
                }

                foreach (String parm in parms.Keys)
                {
                    val = parms.Get(parm);

                    if (val != null && val.Length > 0)
                        if (val == pro || val == dom || val == tok || (att.IndexOf("://") > 0 && val.IndexOf(att) == 0))
                            AddAlert(session, parm, val, att, session.HTTPMethodIs("POST"));
                }
            }
        }

        public override void Check(Session session)
        {
            NameValueCollection parms = null;

            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname))
            {
                if (session.responseCode == 301 || session.responseCode == 302)
                {
                    if (session.oResponse.headers.Exists("location"))
                    {
                        parms = Utility.GetRequestParameters(session);

                        if (parms != null && parms.Keys.Count > 0)
                            CheckUserControllableLocationHeaderValue(session, parms, session.oResponse.headers["location"]);
                    }
                }
            }
        }
    }
}