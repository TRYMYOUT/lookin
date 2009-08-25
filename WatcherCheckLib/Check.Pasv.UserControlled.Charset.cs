// WATCHER
//
// Check.Pasv.UserControlled.Charset.cs
// Checks for places where user-controlled URL or Form POST parameters control content-type charset values.
//
// Copyright (c) 2009 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Collections.Specialized;
using System.Text.RegularExpressions;
using Fiddler;

namespace CasabaSecurity.Web.Watcher.Checks
{
    public class CheckPasvUserControlledCharset : WatcherCheck
    {
        private string alertbody = "";
        private int findingnum;

        public override String GetName()
        {
            return "User Controlled - Charset values.";
        }

        public override String GetDescription()
        {
            String desc = "This check looks at user-supplied input in query string parameters and POST data to " +
                    "identify where Content-Type or meta tag charset declarations might be user-controlled.  " +
                    "Such charset declarations should always be declared by the application.  If an attacker " +
                    "can control the response charset, they could manipulate the HTML to perform XSS or " +
                    "other attacks.";

            return desc;
        }

        private void AddAlert(Session session)
        {
            string name = "User controllable charset";
            string text =

                name +
                "\r\n\r\n" +
                "Risk: High\r\n\r\n" +
                "The page at the following URL: \r\n\r\n" +
                session.url +
                " appears to include user input in: \r\n\r\n" +
                alertbody;

            WatcherEngine.Results.Add(WatcherResultSeverity.High, session.id, session.url, name, text, StandardsCompliance, findingnum);
        }

        private void AssembleAlert(String tag, String attribute, String parm, String val, String context)
        {
            findingnum++;
            alertbody = alertbody + findingnum.ToString() + ") a(n) '"
                + tag +
                "' tag '" +
                attribute +
                "' attribute\r\n\r\n" +
                "The user input found was:\r\n" +
                parm +
                "=" +
                val +
                "\r\n\r\n" +
                "The context was:\r\n" +
                context +
                "\r\n\r\n\r\n";
        }

        private void CheckCharset(NameValueCollection parms, String body, String element, String attribute)
        {
            String att = String.Empty;
            String val = String.Empty;

            // Check HTTP header charset value.  
            // It should come in here with the value of charset= extracted.
            // So no additional parsing is necessary.
            if (element.Equals("Content-Type"))
            {
                foreach (String parm in parms.Keys)
                {
                    val = parms.Get(parm);

                    if (attribute.Equals(val))
                        AssembleAlert(element, attribute, parm, val, "Content-Type HTTP header");

                }
            }

            // Check meta tag charset value.
            else if (element.Equals("meta"))
            {
                foreach (Match m in Utility.GetHtmlTags(body, element))
                {
                    att = Utility.GetHtmlTagAttribute(m.ToString(), attribute);

                    // Only care about meta tags with a content attribute containing a charset value.
                    if (att != null && att.Contains("charset="))
                    {
                        att = att.Substring(att.IndexOf("charset=") + 8).Trim();

                        foreach (String parm in parms.Keys)
                        {
                            val = parms.Get(parm).Trim();

                            if (att.ToLower().Equals(val.ToLower()))
                                AssembleAlert(element, attribute, parm, val, m.ToString());
                        }
                    }
                }
            }
            
            // check XML documents
            else if (element.Equals("\\?xml"))
            {
                foreach (Match m in Utility.GetHtmlTags(body, element))
                {
                    att = Utility.GetHtmlTagAttribute(m.ToString(), attribute).Trim();

                    // Only care about XML encoding declarations.
                    if (att != null)
                    {
                        foreach (String parm in parms.Keys)
                        {
                            val = parms.Get(parm).Trim();

                            if (att.ToLower().Equals(val.ToLower()))
                                AssembleAlert(element, attribute, parm, val, m.ToString());
                        }
                    }
                }
            }
        }

        public override void Check(Session session, UtilityHtmlParser htmlparser)
        {
            NameValueCollection parms = null;
            String body = String.Empty;
            String header = String.Empty;
            alertbody = "";
            findingnum = 0;

            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname))
            {
                if (session.responseCode == 200)
                {
                    if (Utility.IsResponseHtml(session) || Utility.IsResponseXml(session) )
                    {
                        // get the HTTP Content-Type header, charset value
                        header = session.oResponse.headers.GetTokenValue("Content-Type","charset");
                        body = Utility.GetResponseText(session);
                        if (body != null)
                        {
                            parms = GetRequestParameters(session);

                            if (parms != null && parms.Keys.Count > 0)
                            {
                                if (Utility.IsResponseHtml(session))
                                {
                                    CheckCharset(parms, body, "meta", "content");
                                }
                                else if (Utility.IsResponseXml(session))
                                {
                                    CheckCharset(parms, body, "\\?xml", "encoding");
                                }
                            }
                            if (!String.IsNullOrEmpty(header) && parms != null && parms.Keys.Count > 0)
                            {
                                CheckCharset(parms, body, "Content-Type", header);
                            }
                            if (!String.IsNullOrEmpty(alertbody))
                            {
                                AddAlert(session);
                            }
                        }
                    }
                }
            }
        }
    }
}

