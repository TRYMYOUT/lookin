// WATCHER
//
// Check.Pasv.UserControlled.Charset.cs
// Checks for places where user-controlled URL or Form POST parameters control Javascript references.
//
// Copyright (c) 2010 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Collections.Specialized;
using System.Text.RegularExpressions;
using Fiddler;
using Majestic12;

namespace CasabaSecurity.Web.Watcher.Checks
{
    // TODO:  This check serves as a prototype, we need better understanding of which javascript 
    // references to check other than window.open and *.propery.
    public class CheckPasvUserControlledJavascriptProperty : WatcherCheck
    {
        [ThreadStatic] static private string alertbody = "";
        [ThreadStatic] static private int findingnum;

        public CheckPasvUserControlledJavascriptProperty()
        {
            CheckCategory = WatcherCheckCategory.UserControlled;
            LongName = "User Controlled - Javascript property.";
            LongDescription = "This check looks at user-supplied input in query string parameters and POST data to identify where URL's in certain javascript properties (e.g. createElement src) might becontrolled. This provides hot-spot detection for XSS (cross-site scripting) that will require further review by a security analyst to determine exploitability.";
            ShortName = "User controllable javascript property (XSS)";
            ShortDescription = "The page at the following URL appears to contain user input in a javascript property value:\r\n\r\n";
            Reference = "http://websecuritytool.codeplex.com/wikipage?title=Checks#user-controlled-javascript-reference";
            Recommendation = "Do not allow user-input to control javascript source location references.";
        }
        
        private void AddAlert(Session session)
        {
            String name = ShortName;
            String text =

                ShortDescription +
                session.fullUrl +
                "\r\n\r\n" +
                alertbody +
                "\r\n\r\n";

            WatcherEngine.Results.Add(WatcherResultSeverity.High, session.id, session.fullUrl, name, text, StandardsCompliance, findingnum, Reference);
        }

        private void AssembleAlert(String parm, String val, String context)
        {
            findingnum++;
            alertbody = alertbody + findingnum.ToString() + ") The user input found was:\r\n" +
                parm +
                "=" +
                val +
                "\r\n\r\n" +
                "The context was:\r\n" +
                context +
                "\r\n\r\n\r\n";
        }

        private void CheckUserControllableJavascriptProperty(NameValueCollection parms, String att, String context)
        {
            String pro = null;
            String dom = null;
            String tok = null;
            String val = null;

            if (att.Length > 0)
            {

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
                            AssembleAlert(parm, val, context);
                }
            }
        }

        private void CheckUserControllableJavascriptReferenceProperty(NameValueCollection parms, String bod, String property)
        {
            // *.property = "http://www.domain.com"
            foreach (Match m in Regex.Matches(bod, "\\w+?\\." + property + "\\s*?=\\s*?(\'|\").*?(\'|\")", RegexOptions.Singleline))
            {
                Match a = Regex.Match(m.ToString(), "(\'|\").*?(\'|\")");

                if (a.Success)
                    CheckUserControllableJavascriptProperty(parms, Utility.StripQuotes(a.ToString()), m.ToString());
            }
        }

        private void CheckUserControllableJavascriptReferenceWindowOpen(NameValueCollection parms, String bod)
        {
            // window.open('http://www.domain.com', ... )
            foreach (Match m in Regex.Matches(bod, "window\\.open\\s*?\\(\\s*?(\'|\").*?(\'|\").*?\\)", RegexOptions.Singleline))
            {
                Match a = Regex.Match(m.ToString(), "(\'|\").*?(\'|\")");

                if (a.Success)
                    CheckUserControllableJavascriptProperty(parms, Utility.StripQuotes(a.ToString()), m.ToString());
            }
        }

        public override void Check(Session session)
        {
            NameValueCollection parms = null;
            String bod = null;
            alertbody = "";
            findingnum = 0;

            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname))
            {
                if (session.responseCode == 200)
                {
                    parms = Utility.GetRequestParameters(session);

                    if (parms != null && parms.Keys.Count > 0)
                    {
                        if (Utility.IsResponseHtml(session))
                        {
                            UtilityHtmlParser parser = new UtilityHtmlParser();
                            parser.Open(session);
                            if (parser.Parser == null) return;
                            HTMLchunk chunk;

                            while ((chunk = parser.Parser.ParseNext()) != null)
                            {
                                if (chunk.oType == HTMLchunkType.Script)
                                {
                                    CheckUserControllableJavascriptReferenceProperty(parms, chunk.oHTML, "src");
                                    CheckUserControllableJavascriptReferenceProperty(parms, chunk.oHTML, "href");
                                    CheckUserControllableJavascriptReferenceWindowOpen(parms, chunk.oHTML);
                                }
                            }
                            parser.Close();
                        }

                        if (Utility.IsResponseJavascript(session))
                        {
                            CheckUserControllableJavascriptReferenceProperty(parms, bod, "src");
                            CheckUserControllableJavascriptReferenceProperty(parms, bod, "href");
                            CheckUserControllableJavascriptReferenceWindowOpen(parms, bod);
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