// WATCHER
//
// Check.Pasv.Misc.Grep.cs
// Checks user-supplied regex patterns in the HTTP response bodies.
//
// Copyright (c) 2010 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Text.RegularExpressions;
using Fiddler;
using System.Net;
using System.Collections.Generic;
using System.IO;
using System.Windows.Forms;
using System.Security;
using Majestic12;

namespace CasabaSecurity.Web.Watcher.Checks
{
    /// <summary>
    /// Check for dubious comments that warrant further attention.
    /// </summary>
    /// TODO: add finding count
    public class CheckPasvMiscGrep : WatcherCheck
    {
        private StringCheckConfigPanel configpanel;
        String[] defaultstrings = null;
        [ThreadStatic]
        static private string alertbody = "";
        [ThreadStatic]
        static private int findingnum;
        //[ThreadStatic] UtilityHtmlParser parser = new UtilityHtmlParser();


        private volatile List<string> wordlist = new List<string>();

        public CheckPasvMiscGrep()
        {
            configpanel = new StringCheckConfigPanel(this);
            configpanel.Init(defaultstrings, "Case-insensitive regex patterns currently monitored:", "Enter new, case-insensitive regex patterns to monitor for in HTTP response bodies.  NOTE: Watcher will not validate these patterns for you! Make sure they're correct before adding:");
            UpdateWordList();

            CheckCategory = WatcherCheckCategory.None;
            LongName = "Miscellaneous - Check HTTP response body for custom-defined regex patterns.";
            LongDescription = "This check looks at the HTTP resposne body to find matches for your custom-defined regex patterns.  It's up to you to make sure the regex patterns are defined properly, and don't DoS Fiddler!";
            ShortName = "My custom regex match";
            ShortDescription = "Your custom-defined regex pattern had matches at the following URL:\r\n\r\n";
            Reference = "http://websecuritytool.codeplex.com/wikipage?title=Checks#body-grep";
            Recommendation = "This is your check, you tell me!";
        }

        public override System.Windows.Forms.Panel GetConfigPanel()
        {
            System.Windows.Forms.Panel panel = new System.Windows.Forms.Panel();
            panel.Dock = System.Windows.Forms.DockStyle.Fill;
            configpanel.Dock = System.Windows.Forms.DockStyle.Fill;
            panel.Controls.Add(configpanel);
            return panel;
        }

        private void AddAlert(Session session, String pattern, bool error)
        {
            String name = ShortName + ": " + pattern;
            String text = "";
            if (!error)
            {
                text =
                    ShortDescription +
                    session.fullUrl +
                    "\r\n\r\n" +
                    alertbody;
            }
            else
            {
                text =
                    "WARNING: An error was encountered with your regex pattern.  Check and revise the following regex pattern:\r\n\r\n" + 
                    pattern +
                    "\r\n\r\n" +
                    alertbody;
            }
            WatcherEngine.Results.Add(WatcherResultSeverity.Informational, session.id, session.fullUrl, name, text, StandardsCompliance, findingnum, Reference);
        }

        public override void UpdateWordList()
        {
            List<string> list = new List<string>();
            foreach (ListViewItem item in configpanel.stringchecklistBox.Items)
            {
                if (item != null)
                {
                    list.Add(item.Text);
                }
            }
            lock (wordlist)
            {
                wordlist = list;
            }
        }

        private void GrepBody(Session session)
        {
            // modify this list of words to find what you want
            List<string> words;

            // Figure out the response charset
            String charset = Utility.GetHtmlCharset(session);
            String body = "";

            try
            {
                // Set body byte encoding to page charset
                if (!String.IsNullOrEmpty(charset))
                {
                    body = System.Text.Encoding.GetEncoding(charset).GetString(session.responseBodyBytes);
                }
                // if no charset was specified then set o UTF8
                else body = System.Text.Encoding.UTF8.GetString(session.responseBodyBytes);
            }
            // If something goes wrong treat the body as UTF8
            catch (Exception e)
            {
                body = System.Text.Encoding.UTF8.GetString(session.responseBodyBytes);
            }

            lock (wordlist)
            {
                words = new List<string>(wordlist);
            }
            foreach (String w in words)
            {
                try
                {
                    alertbody = "";
                    findingnum = 0;
                    MatchCollection matches = Regex.Matches(body, w, RegexOptions.Compiled | RegexOptions.IgnoreCase);
                    if (matches.Count > 0)
                    {
                        foreach (Match m in matches)
                        {
                            findingnum++;
                            alertbody = alertbody + findingnum.ToString() + ") " + m.ToString() + "\r\n";
                        }
                    }

                    // Add a separate alert for each regex pattern
                    if (!String.IsNullOrEmpty(alertbody))
                    {
                        AddAlert(session, w, false);
                    }
                }
                catch (ArgumentException e)
                {
                    alertbody = "ArgumentException: " + e.Message;
                    AddAlert(session, w, true);
                }
            }
        }

        public override void Check(Session session)
        {

            alertbody = "";
            findingnum = 0;

            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname))
            {
                if (session.responseCode == 200)
                {
                    if ((Utility.IsResponseHtml(session)
                        || Utility.IsResponseCss(session)
                        || Utility.IsResponseJavascript(session)
                        || Utility.IsResponseJson(session)
                        || Utility.IsResponsePlain(session)
                        || Utility.IsResponseXhtml(session)
                        || Utility.IsResponseXml(session))
                        && session.responseBodyBytes.Length > 0)
                    {
                        GrepBody(session);

                    }
                }
            }
        }
    }
}