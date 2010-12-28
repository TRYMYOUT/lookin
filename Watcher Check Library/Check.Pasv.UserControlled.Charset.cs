// WATCHER
//
// Check.Pasv.UserControlled.Charset.cs
// Checks for places where user-controlled URL or Form POST parameters control content-type charset values.
//
// Copyright (c) 2010 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Collections.Specialized;
using System.Text.RegularExpressions;
using Fiddler;
using HtmlAgilityPack;

namespace CasabaSecurity.Web.Watcher.Checks
{
    public class CheckPasvUserControlledCharset : WatcherCheck
    {
        [ThreadStatic] static private string alertbody = "";
        [ThreadStatic] static private int findingnum;

        public CheckPasvUserControlledCharset()
        {
            CheckCategory = WatcherCheckCategory.UserControlled | WatcherCheckCategory.Charset;
            LongName = "User Controlled - Charset values.";
            LongDescription = "This check looks at user-supplied input in query string parameters and POST data to identify where Content-Type or meta tag charset declarations might be user-controlled. Such charset declarations should always be declared by the application. If an attacker can control the response charset, they could manipulate the HTML to perform XSS or other attacks.";
            ShortName = "User controllable charset";
            ShortDescription = "By controlling the character encoding an attacker could manipulate content (e.g. UTF-7) to bypass security filters and inject HTML or javascript.";
            Reference = "http://websecuritytool.codeplex.com/wikipage?title=Checks#user-controlled-charset";
            Recommendation = "Force UTF-8 in all charset declarations.  If user-input is required to decide a charset declaration, ensure that only an allowed list is used.";
        }


        private void AddAlert(Session session)
        {
            string name = ShortName;
            string text = ShortDescription +

                "The page at the following URL: \r\n\r\n" +
                session.fullUrl +
                " appears to include user input in: \r\n\r\n" +
                alertbody;

            WatcherEngine.Results.Add(WatcherResultSeverity.High, session.id, session.fullUrl, name, text, StandardsCompliance, findingnum, Reference);
        }

        // TODO: Fix alert to describe HTTP Content-Type header, right now it's winging it as if it were
        // an HTML node.
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
                "The charset value it controlled was:\r\n" +
                context +
                "\r\n\r\n\r\n";
        }

        private void CheckCharset(NameValueCollection parms, String body, String element, String attribute, UtilityHtmlDocument html)
        {
            String att = String.Empty;
            String val = String.Empty;

            // Check the HTTP Content-Type header
            if (element.ToLower().Equals("content-type"))
            {
                foreach (String parm in parms.Keys)
                {
                    val = parms.Get(parm);

                    if (attribute.Equals(val))
                        AssembleAlert(element, attribute, parm, val, "Content-Type HTTP header");

                }
            }

            // Check HTTP header charset value.  
            // It should come in here with the value of charset= extracted.
            // So no additional parsing is necessary.
            // Check meta tag charset value.
            else if (element.Equals("meta"))
            {
                foreach (HtmlNode node in html.Nodes)
                {
                    if (node.Name.ToLower() == "meta")
                    {
                        if (node.GetAttributeValue("http-equiv","").ToLower() == "content-type")
                        {
                            att = node.GetAttributeValue("content", "");
                            if (!String.IsNullOrEmpty(att) && att.Contains("charset="))
                            {
                                att = att.Substring(att.IndexOf("charset=", StringComparison.InvariantCultureIgnoreCase) + 8).Trim();
                                foreach (String parm in parms.Keys)
                                {
                                    val = parms.Get(parm).Trim();

                                    if (att.ToLower().Equals(val.ToLower()))
                                        AssembleAlert(element, attribute, parm, val, node.OuterHtml);
                                }
                            }
                        }
                    }
                }
            }
            
            // check XML documents
            else if (element.Equals("\\?xml"))
            {
                foreach (HtmlNode node in html.Nodes)
                {
                    if (node.Name.ToLower() == "?xml")
                    {
                        att = node.GetAttributeValue("encoding", "");
                        if (!String.IsNullOrEmpty(att))
                        {
                            foreach (String parm in parms.Keys)
                            {
                                val = parms.Get(parm).Trim();

                                if (att.ToLower().Equals(val.ToLower()))
                                    AssembleAlert(element, attribute, parm, val, node.OuterHtml);
                            }
                        }
                    }
                }
            }
        }

        public override void Check(Session session, UtilityHtmlDocument html)
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
                            parms = Utility.GetRequestParameters(session);

                            if (parms != null && parms.Keys.Count > 0)
                            {
                                if (Utility.IsResponseHtml(session))
                                {
                                    CheckCharset(parms, body, "meta", "content", html);
                                }
                                else if (Utility.IsResponseXml(session))
                                {
                                    CheckCharset(parms, body, "\\?xml", "encoding", html);
                                }
                            }
                            if (!String.IsNullOrEmpty(header) && parms != null && parms.Keys.Count > 0)
                            {
                                CheckCharset(parms, body, "Content-Type", header, html);
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

