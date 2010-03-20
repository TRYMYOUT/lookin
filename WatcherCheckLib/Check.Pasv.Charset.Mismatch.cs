﻿// WATCHER
//
// Check.Pasv.Charset.Mismatch.cs
// Checks for charset mismatches between Header and Content tags.
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
    public class CheckPasvCharsetMismatch : CasabaSecurity.Web.Watcher.WatcherCheck
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
            return "Charset - Detect charset mismatches between the HTTP header and HTML or XML bodies.";
        }

        public override String GetDescription()
        {
            String desc = "This check identifies responses where the HTTP Content-Type header declares a charset " +
                    "different from the charset defined by the body of the HTML or XML.  " +
                    "When there's a charset mismatch between the HTTP header and content body " +
                    "Web browsers can be forced into an undesirable content-sniffing mode " +
                    "to determine the content's correct character set.";

            return desc;
        }

        public override System.Windows.Forms.Panel GetConfigPanel()
        {
            System.Windows.Forms.Panel panel = new System.Windows.Forms.Panel();
            return panel;
        }

        private void AddAlert(Session session)
        {
            string name = "Charset mismatch";
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

        private void CheckContentTypeCharset(String cont, String place, String header)
        {   
            // Normalize the two values we're comparing.
            cont = cont.Trim();
            header = header.Trim();

            switch (place)
            {
                case "html":
                    place = "the HTML content's meta tag";
                    if (cont.IndexOf("charset=") > 0)
                    {
                        cont = cont.Substring(cont.IndexOf("charset=") + 8);
                        // Compare the meta tag charset declaration with the HTTP Header's charset
                        if (!cont.ToLower().Equals(header.ToLower()))
                        {
                            alertbody = alertbody + findingnum.ToString() + ") There was a charset mismatch " +
                                "between the HTTP Header and the HTML Meta tag: '" + 
                                cont + "' and '" + header + "' do not match.\r\n\r\n";
                            findingnum++;
                        }
                    }
                    break;
                case "xml":
                    place = "the XML content's encoding attribute";
                    if (!String.IsNullOrEmpty(cont))
                    {
                        // Compare the meta tag charset declaration with the HTTP Header's charset
                        if (!cont.ToLower().Equals(header.ToLower()))
                        {
                            findingnum++;
                            alertbody = alertbody + findingnum.ToString() + ") There was a charset mismatch " +
                                "between the HTTP Header and the XML encoding declaration: '" +
                                cont + "' and '" + header + "' do not match.\r\n\r\n";
                        }
                    }
                    break;
                default:
                    break;
            }
        }

        //public override void Check(WatcherEngine watcher, Session session, UtilityHtmlParser htmlparser)
        public override void Check(Session session, UtilityHtmlParser htmlparser)
        {
            String body = null;
            String hteq = null;
            String cont = null;
            String enc = null;
            String header = null;
            alertbody = String.Empty;
            findingnum = 0;

            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname))
            {
                if (session.responseCode == 200)
                {
                    if (Utility.UrlNotInList(session.fullUrl, urls))
                    {
                        // We only care about HTML and XML content, see:
                        // http://www.w3.org/International/O-charset
                        //
                        if (Utility.IsResponseHtml(session))
                        {
                            header = session.oResponse.headers.GetTokenValue("Content-Type", "charset");
                            body = Utility.GetResponseText(session);

                            // skip cases where the HTTP Header is null or empty, these are covered by another check.
                            if (body != null && !String.IsNullOrEmpty(header))
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
                                                CheckContentTypeCharset(cont, "html", header);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        else if (Utility.IsResponseXml(session))
                        {
                            header = session.oResponse.headers.GetTokenValue("Content-Type", "charset");
                            body = Utility.GetResponseText(session);

                            // skip cases where the HTTP Header is null or empty, these are covered by another check.
                            if (body != null && !String.IsNullOrEmpty(header))
                            {
                                // need to escape the ? for the regex in GetHtmlTags()
                                foreach (Match m in Utility.GetHtmlTags(body, "\\?xml"))
                                {
                                    enc = Utility.GetHtmlTagAttribute(m.ToString(), "encoding");
                                    if (enc != null)
                                    {
                                        CheckContentTypeCharset(enc, "xml", header);
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
    }
}