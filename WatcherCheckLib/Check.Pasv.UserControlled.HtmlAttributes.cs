// WATCHER
//
// Check.Pasv.UserControlled.HtmlAttributes.cs
// Checks for places where user-controlled URL or Form POST parameters control HTML attributes.
//
// Copyright (c) 2009 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Text.RegularExpressions;
using Fiddler;

namespace CasabaSecurity.Web.Watcher.Checks
{
    public class CheckPasvUserControlledHTMLAttributes : WatcherCheck
    {
        private string alertbody = "";
        private int findingnum;
        
        public override String GetName()
        {
            return "User Controlled - Find user controllable tag attributes.";
        }

        public override String GetDescription()
        {
            String desc = "This check looks at user-supplied input in query string parameters and POST data to " +
                    "identify where certain HTML attribute values might be controlled.  This provides hot-spot " +
                    "detection that will require further review by a security analyst to determine exploitability.  " +
                    "Typical vulnerabilities associated with this phenomena include XSS, but testing will be " +
                    "required to determine if that's possible or not.";

            return desc;
        }

        private void AddAlert(Session session)
        {
            string name = "User Controllable Tag Attribute";
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

        /// <summary>
        /// Mainly looks to see if user-input controls certain attributes.  If the input is a URL, this attempts
        /// to see if the scheme or domain can be controlled.  If it's not, it attempts to see if the attribute
        /// data starts with the user-data.
        /// </summary>
        /// <param name="parms"></param>
        /// <param name="body"></param>
        /// <param name="tag"></param>
        /// <param name="attribute"></param>
        /// <param name="requiredAttribute"></param>
        /// <param name="requiredAttributeValue"></param>
        private void CheckTags(NameValueCollection parms, List<HtmlElement> listOfTags)
        {
            String att = null;
            String val = null;
            String pro = null;
            String dom = null;
            String tok = null;

            foreach (HtmlElement element in listOfTags)
            {
                Dictionary<String, List<String>>.KeyCollection keyCollAtt = element.att.Keys;

                foreach (String attribute in keyCollAtt)
                {
                    foreach (String value in element.att[attribute])
                    {
                        if (value != null)
                        {
                            att = value;
                            // special handling of meta tag
                            if (element.tag == "meta" && attribute == "content")
                            {
                                if (Regex.IsMatch(value.ToLower(), "^\\s*?[0-9]+?\\s*?;\\s*?url\\s*?=.*"))
                                {
                                    att = value.Substring(value.ToLower().IndexOf("url=") + 4);
                                    att = att.Trim();
                                }
                            }
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
                                // It's a local path, or it's not a resource.
                                // Proceed later expecting the attribute value
                                // might star with the user-input.

                                foreach (String parm in parms.Keys)
                                {
                                    val = parms.Get(parm);

                                    // Special handling of meta tag.
                                    // If I were just looking to see if the meta tag 'contains' the user input,
                                    // we'd wind up with lots of false positives.
                                    // To avoid this, I  parse the meta tag values based on a set of delimeters,
                                    // such as ; =  and ,.  This is similar to what the Cookie poisoning 
                                    // check does.
                                    if (element.tag == "meta" && attribute == "content")
                                    {
                                        // False Positive Reduction
                                        // We have a check for meta tag charset already, so get out of here.
                                        if (att.Contains("charset")) continue;


                                        string[] split = att.Split(new Char[] { ';', '=', ',' });

                                        foreach (String s in split)
                                        {
                                            if (s.Equals(val))
                                                AssembleAlert(element.tag, attribute, parm, val, value);
                                        }
                                    }

                                    // False Positive Reduction
                                    // I want the value length to be greater than 1 to avoid all the false positives
                                    // we're seeing when the input is limited to a single character.
                                    if (val != null && val.Length > 1)
                                    {
                                        // See if the user-input can control the start of the attribute data.
                                        if (att.StartsWith(val) || val == pro || val == dom || val == tok || (att.IndexOf("://") > 0 && val.IndexOf(att) == 0))
                                        {
                                            AssembleAlert(element.tag, attribute, parm, val, value);
                                        }
                                    }
                                    // Make up for the false positive reduction by by being 
                                    // sure to catch cases where a single character may control the attribute.
                                    // UPDATE: This case is too common and annoyingly rife with false positives.

                                    // if (val.Length == 1 && att.Equals(val) )
                                    // {
                                    //    AssembleAlert(element.tag, attribute, parm, val, value);
                                    // }
                                }
                            }
                        }
                    }
                }
            }
        }

        public override void Check(Session session, UtilityHtmlParser htmlparser)
        {
            NameValueCollection parms = null;
            String body = null;
            alertbody = "";
            findingnum = 0;
            List<HtmlElement> htmlElements = htmlparser.HtmlElementCollection;

            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname))
            {
                if (session.responseCode == 200)
                {
                    if (Utility.IsResponseHtml(session))
                    {
                        body = Utility.GetResponseText(session);
                        if (body != null)
                        {
                            parms = GetRequestParameters(session);

                            if (parms != null && parms.Keys.Count > 0)
                            {
                                CheckTags(parms, htmlElements);
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