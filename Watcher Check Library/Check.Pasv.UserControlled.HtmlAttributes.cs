// WATCHER
//
// Check.Pasv.UserControlled.HtmlAttributes.cs
// Checks for places where user-controlled URL or Form POST parameters control HTML attributes.
//
// Copyright (c) 2010 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Text.RegularExpressions;
using HtmlAgilityPack;
using Fiddler;

namespace CasabaSecurity.Web.Watcher.Checks
{
    public class CheckPasvUserControlledHTMLAttributes : WatcherCheck
    {
        [ThreadStatic] static private string alertbody = "";
        [ThreadStatic] static private int findingnum;

        public CheckPasvUserControlledHTMLAttributes()
        {
            CheckCategory = WatcherCheckCategory.UserControlled;
            LongName = "User Controlled - HTML element attributes (potential XSS).";
            LongDescription = "This check looks at user-supplied input in query string parameters and POST data to identify where certain HTML attribute values might be controlled. This provides hot-spot detection for XSS (cross-site scripting) that will require further review by a security analyst to determine exploitability. ";
            ShortName = "User controllable HTML element attribute (potential XSS)";
            ShortDescription = "User-controlled HTML attribute values were found.  Try injecting special characters such as ', \", <, and > to see if XSS might be possible.  The page at the following URL:\r\n\r\n";
            Reference = "http://websecuritytool.codeplex.com/wikipage?title=Checks#user-controlled-html-attribute";
            Recommendation = "Validate all input and sanitize output it before writing to any HTML attributes.";
        }

        private void AddAlert(Session session)
        {
            string name = ShortName;
            string text =

                ShortDescription +
                session.fullUrl + 
                "\r\n\r\nappears to include user-controlled input in: \r\n\r\n" +
                alertbody;

            WatcherEngine.Results.Add(WatcherResultSeverity.Informational, session.id, session.fullUrl, name, text, StandardsCompliance, findingnum, Reference);
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
                "The user-controlled value was:\r\n" +
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
        /// 
      
        private void CheckAttributeValues(NameValueCollection parms, UtilityHtmlDocument html)
        {
            /// The attribute value
            String att = null;
            String val = null;

            foreach (HtmlNode node in html.Nodes)
            {
                foreach (HtmlAttribute attribute in node.Attributes)
                {
                    att = Utility.ToSafeLower(attribute.Value);
                    if (!String.IsNullOrEmpty(att))
                    {
                        foreach (String parm in parms.Keys)
                        {
                            val = parms.Get(parm);
                            val = Utility.ToSafeLower(val);

                            // Special handling of meta tag.
                            // If I were just looking to see if the meta tag 'contains' the user input,
                            // we'd wind up with lots of false positives.
                            // To avoid this, I  parse the meta tag values based on a set of delimeters,
                            // such as ; =  and ,.  This is similar to what the Cookie poisoning 
                            // check does.
                            if (node.Name.ToLower() == "meta" && attribute.Name.ToLower() == "content")
                            {
                                // False Positive Reduction
                                // We have a check for meta tag charset already, so get out of here.
                                if (att.Contains("charset")) continue;


                                string[] split = att.Split(new Char[] { ';', '=', ',' });

                                foreach (String s in split)
                                {
                                    if (s.Equals(val))
                                        AssembleAlert(node.Name, attribute.Name, parm, val, att);
                                }
                            }

                            // False Positive Reduction
                            // I want the value length to be greater than 1 to avoid all the false positives
                            // we're seeing when the input is limited to a single character.
                            if (val != null && val.Length > 1)
                            {
                                // See if the user-input can control the start of the attribute data.
                                if (att.StartsWith(val) || att.Equals(val) || att.Contains(val))
                                {
                                    AssembleAlert(node.Name, attribute.Name, parm, val, att);
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

            /*
            foreach (HtmlElement element in listOfTags)
            {
                Dictionary<String, List<String>>.KeyCollection keyCollAtt = element.att.Keys;

                foreach (String attribute in keyCollAtt)
                {
                    foreach (String value in element.att[attribute])
                    {
                        if (value != null)
                        {
                            att = Utility.ToSafeLower(value);
                            // special handling of meta tag
                            if (element.tag.ToLower() == "meta" && attribute.ToLower() == "content")
                            {
                                if (Regex.IsMatch(value.ToLower(), "^\\s*?[0-9]+?\\s*?;\\s*?url\\s*?=.*"))
                                {
                                    att = value.Substring(value.IndexOf("url=", StringComparison.InvariantCultureIgnoreCase) + 4);
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
                                    val = Utility.ToSafeLower(val);

                                    // Special handling of meta tag.
                                    // If I were just looking to see if the meta tag 'contains' the user input,
                                    // we'd wind up with lots of false positives.
                                    // To avoid this, I  parse the meta tag values based on a set of delimeters,
                                    // such as ; =  and ,.  This is similar to what the Cookie poisoning 
                                    // check does.
                                    if (Utility.ToSafeLower(element.tag) == "meta" && Utility.ToSafeLower(attribute) == "content")
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
            */
        }
       
        public override void Check(Session session, UtilityHtmlDocument html)
        {
            NameValueCollection parms = null;
            alertbody = "";
            findingnum = 0;


            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname))
            {
                if (session.responseCode == 200)
                {
                    // Make sure that we have at least one HTML element.
                    if (html.Nodes.Count > 0)
                    {
                        parms = Utility.GetRequestParameters(session);

                        if (parms != null && parms.Keys.Count > 0)
                        {
                            CheckAttributeValues(parms, html);
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