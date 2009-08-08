// WATCHER
//
// Check.Pasv.UserControlled.Cookie.cs
// Checks for places where user-controlled URL or Form POST parameters control cookie values.
//
// Copyright (c) 2009 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Collections.Specialized;
using Fiddler;

namespace CasabaSecurity.Web.Watcher.Checks
{
    public class CheckPasvUserControlledCookie : WatcherCheck
    {
        private string alertbody = String.Empty;
        private int findingnum;
        private bool isPost;

        public override String GetName()
        {
            return "User Controlled - Cookie poisoning.";
        }

        public override String GetDescription()
        {
            String desc = "This check looks at user-supplied input in query string parameters and POST data to " +
                    "identify where cookie parameters might be controlled.  " +
                    "This is called a cookie poisoning attack, and becomes exploitable when an attacker can " +
                    "manipulate the cookie in nafarious ways.  In some cases this will not be exploitable, " +
                    "however, allowing URL parameters to set cookie values is generally considered a bug.";

            return desc;
        }

        private void AddAlert(Session session)
        {
            String name = "User Controllable Cookie (cookie poisoning attack)";
            if (!isPost)
            {
                String text =

                    name +
                    "\r\n\r\n" +
                    "Risk: High\r\n\r\n" +
                    "An attacker may be able to poison cookie values through URL parameters.  This was identified at: \r\n\r\n" +
                    session.url +
                    "\r\n\r\n" +
                    alertbody;

                WatcherEngine.Results.Add(WatcherResultSeverity.High, session.id, session.url, name, text, StandardsCompliance, findingnum);
            }
            else
            {
                String text =
                    name +
                    "\r\n\r\n" +
                    "Risk: Informational\r\n\r\n" +
                    "An attacker may be able to poison cookie values through POST parameters.  This was identified at: ." +
                    "To test if this is a more serious issue, you should try resending that request " +
                    "as a GET, with the POST parameter included as a query string parameter." + 
                    " For example:  http://nottrusted.com/page?value=maliciousInput.\r\n\r\n" +
                    "This was identified at:\r\n\r\n" +
                    session.url +
                    "\r\n\r\n" +
                    alertbody;

                WatcherEngine.Results.Add(WatcherResultSeverity.Informational, session.id, session.url, name, text, StandardsCompliance, findingnum);
            }
        }

        private void AssembleAlert(String parm, String val, String context)
        {
            findingnum++;
            alertbody = alertbody + findingnum.ToString() + ") User-input was found in the following cookie:\r\n" +
                context +
                "\r\n\r\nThe user input was:\r\n" +
                parm + "=" + val +
                "\r\n\r\n";
        }

        public void CheckUserControllableCookieHeaderValue(Session session, NameValueCollection parms, String part, String cookie)
        {
            if (cookie.Length > 0)
            {
                String val = String.Empty;

                foreach (String parm in parms.Keys)
                {
                    val = parms.Get(parm);

                    // False Positive Reduction - see bug ID 1471
                    // Need to ignore parameters equal to empty value (e.g. name= )
                    // otherwise we'll wind up with false positives when cookie
                    // values are also set to empty.  
                    // 
                    // False Positive Reduction
                    // Ignore values not greater than 1 character long.  It seems to
                    // be common that value=0 and value=/ type stuff raise a false
                    // positive.
                    if (!String.IsNullOrEmpty(val) && val.Length > 1 && part.Equals(val))
                        AssembleAlert(parm, val, cookie);
                }
            }
        }

        public override void Check(Session session, UtilityHtmlParser htmlparser)
        {
            NameValueCollection parms = null;
            String cookie = null;
            // Common delimiters in cookies.  E.g. name=value;name2=v1|v2|v3
            Char[] delims = {';','=','|'};
            // Array to hold the parsed out cookie.
            String[] split = { };
            isPost = session.HTTPMethodIs("POST");
            alertbody = String.Empty;
            // Reset finding counter
            findingnum = 0;

            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname))
            {
                if (session.oResponse.headers.Exists("set-cookie"))
                {
                    // get the query string and POST params if cookies were set
                    parms = GetRequestParameters(session);

                    // loop through each header to find the cookies
                    // TODO: Does Fiddler expose a cookie collection?
                    foreach (HTTPHeaderItem c in session.oResponse.headers)
                    {
                        if (c.Name.ToLower() == "set-cookie")
                        {
                            // Cookies are commonly URL encoded, maybe other encodings.
                            // TODO: apply other decodings?  htmlDecode, etc.
                            cookie = c.Value;
                            cookie = System.Web.HttpUtility.UrlDecode(cookie);

                            // Now we have a cookie.  Parse it out into an array.
                            // I'm doing this to avoid false positives.  By parsing
                            // the cookie at each delimiter, I'm checking to see that
                            // we can match user-input directly.  Otherwise we'd find
                            // all the cases where the cookie simply 'contained' user input,
                            // which leads to many false positives.
                            // For example, if user input was 'number=20' and the cookie was
                            // value=82384920 then we don't want to match.  I want precise
                            // matches such as value=20.
                            split = cookie.Split(delims);
                            foreach (String s in split)
                            {
                                if (parms != null && parms.Keys.Count > 0)
                                    CheckUserControllableCookieHeaderValue(session, parms, s, cookie);
                            }
                        }
                    }
                }
                if (!String.IsNullOrEmpty(alertbody))
                {
                    AddAlert(session);
                }
            }
        }
    }
}