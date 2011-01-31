// WATCHER
//
// Check.Pasv.UserControlled.JavasriptEvent.cs
// Checks for places where user-controlled URL or Form POST parameters control Javascript on* events.
//
// Copyright (c) 2010 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Text.RegularExpressions;
using System.Windows.Forms;
using Fiddler;

namespace CasabaSecurity.Web.Watcher.Checks
{
    public class CheckPasvUserControlledJavascriptEvent : WatcherCheck
    {
        [ThreadStatic] static private string alertbody = String.Empty;
        [ThreadStatic] static private int findingnum;

        public CheckPasvUserControlledJavascriptEvent()
        {
            CheckCategory = WatcherCheckCategory.UserControlled;
            LongName = "User Controlled - Javascript event (XSS).";
            LongDescription = "This check looks at user-supplied input in query string parameters and POST data to identify where certain HTML attribute values might be controlled. This provides hot-spot detection for XSS (cross-site scripting) that will require further review by a security analyst to determine exploitability. ";
            ShortName = "User controllable javascript event (XSS)";
            ShortDescription = "User-controlled javascript event(s) was found.  Exploitability will need to be manually determined.  The page at the following URL:\r\n\r\n";
            Reference = "http://websecuritytool.codeplex.com/wikipage?title=Checks#user-javascript-event";
            Recommendation = "Validate all input and sanitize output it before writing to any Javascript on* events.";
        }
        
        private void AddAlert(Session session)
        {
            string name = ShortName;
            string text =

                ShortDescription +
                session.fullUrl +
                "\r\n\r\nincludes the following Javascript events which may be attacker-controllable: \r\n\r\n" +
                alertbody;

            WatcherEngine.Results.Add(WatcherResultSeverity.High, session.id, session.fullUrl, name, text, StandardsCompliance, findingnum, Reference);
        }

        private void AssembleAlert(String jsevent, String parm, String attribute)
        {
            findingnum++;
            alertbody = alertbody + findingnum.ToString() + ") User-input was found in the following data of an '" +
                jsevent + "' event:\r\n" +
                attribute +
                "\r\n\r\nThe user input was:\r\n" +
                parm +
                "\r\n\r\n";
        }

        public void ParseJavascriptEvent(String attribute, String value, String jsevent)
        {
            // Try some rudimentary parsing of the Javascript event
            // so we can find the user-input.
            string[] split = attribute.Split(new Char[] { ';', '=', ',', ':' });

            foreach (String s in split)
            {
                if (s.ToLower().Equals(value))
                    AssembleAlert(jsevent, value, s);
            }

        }

        public override void Check(Session session)
        {
            NameValueCollection parms = null;
            String body = null;
            alertbody = String.Empty;
            findingnum = 0;
            String att = null;
            String val = null;
            List<String> eventlist = new List<String>(new String[]{"onabort", "onbeforeunload", "onblur", "onchange", "onclick", "oncontextmenu", "ondblclick", 
                "ondrag", "ondragend", "ondragenter", "ondragleave", "ondragover", "ondragstart", "ondrop", "onerror",
                "onfocus", "onhashchange", "onkeydown", "onkeypress", "onkeyup", "onload", "onmessage", "onmousedown", 
                "onmousemove", "onmouseout", "onmouseover", "onmouseup", "onmousewheel", "onoffline", "ononline", "onpopstate",
                "onreset", "onresize", "onscroll", "onselect", "onstorage", "onsubmit", "onunload"
            });

            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname))
            {
                if (session.responseCode == 200)
                {
                    if (Utility.IsResponseHtml(session))
                    {
                        body = Utility.GetResponseText(session);
                        if (body != null)
                        {
                            parms = Utility.GetRequestParameters(session);

                            if (parms != null && parms.Keys.Count > 0)
                            {
                                foreach (Match m in Utility.GetHtmlTags(body, ".*?"))
                                {
                                    foreach (String jsevent in eventlist) 
                                    {
                                        if (m.ToString().ToLower().Contains(jsevent))
                                        {
                                            att = Utility.GetHtmlTagAttribute(m.ToString(), jsevent);
                                            if (att.Length > 0)
                                            {
                                                foreach (String parm in parms.Keys)
                                                {
                                                    val = parms.Get(parm).ToLower();
                                                    if (val != null && val.Length > 0)
                                                    {
                                                        ParseJavascriptEvent(att, val, jsevent);
                                                    }
                                                }
                                            }
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
}