// WATCHER
//
// Check.Pasv.Charset.Utf8.cs
// Checks that UTF-8 is declared in HTTP, HTML, and XML.
//
// Copyright (c) 2009 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Text;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Globalization;
using System.Windows.Forms;
using Fiddler;

namespace CasabaSecurity.Web.Watcher.Checks
{
    /// <summary>
    /// Look for places where a charset is not explicitly set to UTF-8 in an HTTP response for HTML/XML content.
    /// Check the HTTP Content-Type header as well as the body's meta tag.
    /// 
    /// TODO: Ensure we're not flagging non-HTML/XML responses, like images.
    /// </summary>
    public class CheckPasvCharsetUTF8 : WatcherCheck
    {
        // we want to avoid doing these checks over and over for the same URL.
        // In other words, we don't want to keep checking the same URL just because
        // a query string parameter changed.
        // TODO: this is a problem because we could miss stuff.  If a certain qs param
        // causes different content to be returned, we'll miss it.  I think we're safe
        // against the majority of cases right now.

        // this list is cleared when the Clear button is clicked in the form.
        private List<String> urls = new List<String>();
        public List<String> Urls { get { return this.urls; } }
        private String alertbody;
        private int findingnum;

        public override String GetName()
        {
            return "Charset - Charset not explicitly set to UTF-8 in HTML/XML content.";
        }

        public override String GetDescription()
        {
            String desc = "This check identifies HTTP headers, meta tags, and XML documents that don't explicitly " +
                    "set a charset value to UTF-8.  UTF-8 is supported in all major Web browsers today, and from a security " +
                    "perspective it is the preferred charset for most Web-applications.  When a charset is not " +
                    "explicitly declared, Web browsers are forced into an undesirable content-sniffing mode " +
                    "to determine the content's character set.";

            return desc;
        }

        public override System.Windows.Forms.Panel GetConfigPanel()
        {
            System.Windows.Forms.Panel panel = new System.Windows.Forms.Panel();
            return panel;
        }

        private void AddAlert(Session session)
        {
            string name = "Charset not UTF-8";
            string text =

                name +
                "\r\n\r\n" +
                "Risk: Informational\r\n\r\n" +
                "The response to the following request did not explicitly set the character set as UTF-8:\r\n\r\n" +
                session.url +
                "\r\n\r\n" +
                "The following issue(s) were identified:" +
                "\r\n\r\n" +
                alertbody;

            WatcherEngine.Results.Add(WatcherResultSeverity.Informational, session.id, session.url, name, text, StandardsCompliance, findingnum);
        }

        public override void Clear()
        {
            urls = new List<String>();
        }

        private void CheckContentTypeCharset(String cont, String place)
        {
            cont = cont.Trim().ToLower();
            switch (place)
            {
                case "header":
                    place = "the HTTP Content-Type header";
                    goto default;
                //break;
                case "html":
                    place = "the HTML content's meta tag";
                    goto default;
                //break;
                case "xml":
                    place = "the XML content's encoding attribute";
                    if (String.IsNullOrEmpty(cont))
                    {
                        findingnum++;
                        alertbody = alertbody + findingnum.ToString() + ") No charset was specified in " + place + ".\r\n\r\n";  
                    }
                    else
                    {
                        if (cont != "utf-8")
                        {
                            findingnum++;
                            alertbody = alertbody + findingnum.ToString() + ") The charset specified was not utf-8 in " + place + ": \"" + cont + "\".\r\n\r\n";
                        }
                    }
                    break;
                default:
                    if (cont.IndexOf("charset=") < 0)
                    {
                        alertbody = alertbody + findingnum.ToString() + ") No charset was specified in " + place + ".\r\n\r\n";
                        findingnum++;
                    }
                    else
                    {
                        cont = cont.Substring(cont.IndexOf("charset=") + 8);
                        if (cont != "utf-8")
                        {
                            alertbody = alertbody + findingnum.ToString() + ") The charset specified was not utf-8 in " + place + ": \"" + cont + "\".\r\n\r\n";
                            findingnum++;
                        }
                    }
                    break;
            }
        }

        public override void Check(Session session, UtilityHtmlParser htmlparser)
        {
            String body = null;
            String hteq = null;
            String cont = null;
            String enc = null;
            bool flag = false;
            alertbody = "";
            findingnum = 0;

            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname))
            {
                if ((Utility.IsResponseHtml(session) || Utility.IsResponseXml(session)) && Utility.UrlNotInList(session.fullUrl, urls))
                {
                    // We only care about HTML and XML content, see:
                    // http://www.w3.org/International/O-charset
                    //
                    if (Utility.IsResponseHtml(session))
                    {
                        // IsResponse* functions fail if no content-type header, so, if here, we know we have content-type header value (either html or xml).
                        CheckContentTypeCharset(session.oResponse.headers["content-type"], "header");

                        body = Utility.GetResponseText(session);
                        if (body != null)
                        {
                            foreach (Match m in Utility.GetHtmlTags(body, "meta"))
                            {
                                hteq = Utility.GetHtmlTagAttribute(m.ToString(), "http-equiv");
                                if (hteq != null)
                                {
                                    if (hteq.Trim().ToLower(CultureInfo.InvariantCulture) == "content-type")
                                    {
                                        cont = Utility.GetHtmlTagAttribute(m.ToString(), "content");
                                        if (cont != null)
                                        {
                                            CheckContentTypeCharset(cont, "html");

                                            flag = true;
                                        }
                                    }
                                }
                            }

                            if (!flag)
                            {
                                //AddAlert(watcher, session, "Content type and/or charset not defined in meta tag.");
                                alertbody = alertbody + findingnum.ToString() + ") Content type and/or charset not defined in meta tag.\r\n";
                                findingnum++;
                            }
                        }
                    }
                    else if (Utility.IsResponseXml(session))
                    {
                        // IsResponse* functions fail if no content-type header, so, if here, we know we have content-type header value (either html or xml).
                        CheckContentTypeCharset(session.oResponse.headers["content-type"], "header");

                        body = Utility.GetResponseText(session);
                        if (body != null)
                        {
                            // need to escape the ? for the regex in GetHtmlTags()
                            foreach (Match m in Utility.GetHtmlTags(body, "\\?xml"))
                            {
                                enc = Utility.GetHtmlTagAttribute(m.ToString(), "encoding");
                                if (enc != null)
                                {
                                    CheckContentTypeCharset(enc, "xml");
                                    flag = true;
                                }
                            }

                            if (!flag)
                            {
                                //AddAlert(watcher, session, "Content type and/or charset not defined in <?xml version=\"1.0\" encoding=\"utf-8\" ?>.");
                                alertbody = alertbody + findingnum.ToString() + ") Content type and/or charset not defined as <?xml version =\"1.0\" encoding=\"utf-8\" ?>.\r\n";
                                findingnum++;
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
}