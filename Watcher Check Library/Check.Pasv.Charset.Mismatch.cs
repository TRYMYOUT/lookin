// WATCHER
//
// Check.Pasv.Charset.Mismatch.cs
// Checks for charset mismatches between Header and Content tags.
//
// Copyright (c) 2010 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Text;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Globalization;
using System.Windows.Forms;
using Fiddler;
using Majestic12;

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
        private volatile List<String> urls = new List<String>();
        public List<String> Urls { get { return this.urls; } }
        [ThreadStatic] static private String alertbody;
        [ThreadStatic] static private int findingnum;
        //[ThreadStatic] UtilityHtmlParser parser = new UtilityHtmlParser();

        public CheckPasvCharsetMismatch()
        {
            CheckCategory = WatcherCheckCategory.Charset;
            LongName = "Charset - Detect charset mismatches between the HTTP header and HTML or XML bodies.";
            LongDescription = "This check identifies responses where the HTTP Content-Type header declares a charset different from the charset defined by the body of the HTML or XML. When there's a charset mismatch between the HTTP header and content body Web browsers can be forced into an undesirable content-sniffing mode to determine the content's correct character set.";
            ShortName = "Charset mismatch";
            ShortDescription = "The response to the following request declared two different charsets that did not match:\r\n\r\n";
            Reference = "http://websecuritytool.codeplex.com/wikipage?title=Checks#charset-mismatch";
            Recommendation = "Force UTF-8 for all text content, such as HTML and XML.";
        }

        public override System.Windows.Forms.Panel GetConfigPanel()
        {
            // No special configuration for this check
            return base.GetConfigPanel();
        }

        private void AddAlert(Session session)
        {
            string name = "Charset mismatch";
            string text =
                ShortDescription +
                session.fullUrl +
                "\r\n\r\n" +
                "The following issue(s) were identified:" +
                "\r\n\r\n" +
                alertbody;

            WatcherEngine.Results.Add(WatcherResultSeverity.Informational, session.id, session.fullUrl, name, text, StandardsCompliance, findingnum, Reference);
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
                    if (cont.IndexOf("charset=", StringComparison.InvariantCultureIgnoreCase) > 0)
                    {
                        cont = cont.Substring(cont.IndexOf("charset=", StringComparison.InvariantCultureIgnoreCase) + 8);
                        // Compare the meta tag charset declaration with the HTTP Header's charset
                        if (!cont.ToLower().Equals(header.ToLower()))
                        {
                            findingnum++;
                            alertbody = alertbody + findingnum.ToString() + ") There was a charset mismatch " +
                                "between the HTTP Header and the HTML Meta tag: '" + 
                                cont + "' and '" + header + "' do not match.\r\n\r\n";
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
        public override void Check(Session session)
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

                            // skip cases where the HTTP Header is null or empty, these are covered by another check.
                            if (session.responseBodyBytes.Length > 0 && !String.IsNullOrEmpty(header))
                            {
                                UtilityHtmlParser parser = new UtilityHtmlParser();
                                parser.Open(session);
                                HTMLchunk chunk;
                                while ((chunk = parser.Parser.ParseNextTag()) != null)
                                {
                                    if (chunk.oType == HTMLchunkType.OpenTag && chunk.sTag == "meta")
                                    {
                                        if (chunk.oParams.ContainsKey("http-equiv") && chunk.oParams.ContainsKey("content"))
                                        {
                                            hteq = chunk.oParams["http-equiv"].ToString();
                                            if (hteq.ToString().Equals("content-type", StringComparison.InvariantCultureIgnoreCase))
                                            {
                                                cont = chunk.oParams["content"].ToString();
                                                if (!String.IsNullOrEmpty(cont))
                                                {
                                                    CheckContentTypeCharset(cont, "html", header);
                                                }

                                            }
                                        }
                                    }
                                }
                                parser.Close();
                            }
                        }
                        else if (Utility.IsResponseXml(session))
                        {
                            header = session.oResponse.headers.GetTokenValue("Content-Type", "charset");

                            // skip cases where the HTTP Header is null or empty, these are covered by another check.
                            if (session.responseBodyBytes.Length > 0 && !String.IsNullOrEmpty(header))
                            {
                                UtilityHtmlParser parser = new UtilityHtmlParser();
                                parser.Open(session);
                                HTMLchunk chunk;
                                while ((chunk = parser.Parser.ParseNextTag()) != null)
                                {
                                    if (chunk.oType == HTMLchunkType.OpenTag && chunk.sTag == "?xml")
                                    {
                                        if (chunk.oParams.ContainsKey("encoding"))
                                        {
                                            enc = chunk.oParams["encoding"].ToString();
                                            if (!String.IsNullOrEmpty(enc))
                                            {
                                                CheckContentTypeCharset(enc, "xml", header);
                                            }
                                        }
                                    }
                                }
                                parser.Close();
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