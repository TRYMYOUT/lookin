// WATCHER
//
// Check.Pasv.UserControlled.JavasriptEvent.cs
// Checks for places where user-controlled URL or Form POST parameters control Javascript on* events.
//
// Copyright (c) 2009 Casaba Security, LLC
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
        private string alertbody = String.Empty;
        private int findingnum;        

        public override String GetName()
        {
            return "User Controlled - Find user controllable values in Javascript Event.";
        }

        public override String GetDescription()
        {
            String desc = "This check looks at user-supplied input in query string parameters and POST data to " +
                    "identify where certain javascript events (e.g. onclick) might be controlled.  This provides hot-spot " +
                    "detection that will require further review by a security analyst to determine exploitability.  " +
                    "Typical vulnerabilities associated with this phenomena include XSS, but testing will be " +
                    "required to determine if that's possible or not.";

            return desc;
        }

        private void AddAlert(Session session)
        {
            string name = "User Controllable Javascript Event";
            string text =

                name +
                "\r\n\r\n" +
                "Risk: High\r\n\r\n" +
                "The page at the following URL: \r\n\r\n" +
                session.url +
                "\r\n\r\nincludes the following Javascript events which may be attacker-controllable: \r\n\r\n" +
                alertbody;

            WatcherEngine.Results.Add(WatcherResultSeverity.High, session.id, session.url, name, text, StandardsCompliance, findingnum);
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
                if (attribute.Equals(value))
                    AssembleAlert(jsevent, value, attribute);
            }

        }

        public override void Check(Session session, UtilityHtmlParser htmlparser)
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
                            parms = GetRequestParameters(session);

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