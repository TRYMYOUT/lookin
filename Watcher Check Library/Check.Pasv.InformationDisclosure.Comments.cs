// WATCHER
//
// Check.Pasv.InformationDisclosure.Comments.cs
// Checks for potentially interesting comments.
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

namespace CasabaSecurity.Web.Watcher.Checks
{
    /// <summary>
    /// Check for dubious comments that warrant further attention.
    /// </summary>
    /// TODO: add finding count
    public class CheckPasvInformationDisclosureComments : WatcherCheck
    {
        private StringCheckConfigPanel configpanel;
        String[] defaultstrings = { "BUG", "TODO", "HACK", "FIX", "XXX", "DEBUG", "dumb", "crap", "sucks", "holy", "stupid" };
        [ThreadStatic] static private string alertbody = "";
        [ThreadStatic] static private int findingnum;


        private volatile List<string> wordlist = new List<string>();

        public CheckPasvInformationDisclosureComments()
        {
            configpanel = new StringCheckConfigPanel(this);
            configpanel.Init(defaultstrings, "Dubious Comment Words:", "Enter new words to watch for here:");
            UpdateWordList();
            
            CheckCategory = WatcherCheckCategory.InfoDisclosure;
            LongName = "Information Disclosure - Check for dubious comments that warrant further attention.";
            LongDescription = "This check looks for common patterns in HTML and javascript comments that may be useful to inspect in a security review or audit. This performs a pattern match looking for a list of words like BUG, TODO, and profanity. You can configure the list of words to search.";
            ShortName = "Dubious comments were found";
            ShortDescription = "Curious looking comments were found at the following URL:\r\n\r\n";
            Reference = "http://websecuritytool.codeplex.com/wikipage?title=Checks#information-disclosure-in-comments";
            Recommendation = "Scrub all comments before pushing to production.";
        }

        public override System.Windows.Forms.Panel GetConfigPanel()
        {
            System.Windows.Forms.Panel panel = new System.Windows.Forms.Panel();
            panel.Dock = System.Windows.Forms.DockStyle.Fill;
            configpanel.Dock = System.Windows.Forms.DockStyle.Fill;
            panel.Controls.Add(configpanel);
            return panel;
        }

        private void AddAlert(Session session)
        {
            String name = ShortName;
            String text =
                ShortDescription +
                session.fullUrl +
                "\r\n\r\n" +
                "The context was (up to 512 bytes following displayed):\r\n\r\n" +
                alertbody;

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

        private void CheckComment(Session session, String comment)
        {
            StringComparer comparer = StringComparer.InvariantCultureIgnoreCase;
            int length;
            // modify this list of words to find what you want
            List<string> words;

            // track the last comment reviewed, so we can skip duplicates in cases like:
            // //this is a BUG comment with many keywords XXX TODO
            //string lastcomment = String.Empty;

            lock (wordlist)
            {
                words = new List<string>(wordlist);
            }
            foreach (String w in words)
            {
                Match m = Regex.Match(comment, "[\\/]?\\b" + w + "\\b", RegexOptions.Multiline | RegexOptions.Compiled | RegexOptions.IgnoreCase);
                if (m.Success)
                {
                    length = comment.Trim().Length;
                    length = length - m.Index;
                    length--;
                    if (length > 512)
                    {
                        length = 512;
                    }
                    findingnum++;
                    //alertbody = alertbody + findingnum.ToString() + ") " + comment.Trim().Substring(m.Index, length) + "\r\n\r\n";
                    alertbody = alertbody + findingnum.ToString() + ") " + comment.Trim().Substring(m.Index, length) + "\r\n\r\n";
                    return;
                }                
            }
        }

        public override void Check(Session session, UtilityHtmlParser htmlparser)
        {
            String body = null;
            String comment = null;
            String[] scriptBlocks = null;

            alertbody = "";
            findingnum = 0;

            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname))
            {
                if (session.responseCode == 200)
                {
                    if (Utility.IsResponseHtml(session) || Utility.IsResponseJavascript(session))
                    {
                        body = Utility.GetResponseText(session);
                        if (body != null)
                        {
                            // Look at text/html responses
                            if (Utility.IsResponseHtml(session))
                            {
                                foreach (Match comments in Utility.GetHtmlComment(body))
                                {
                                    comment = comments.ToString();
                                    if (comment != null)
                                    {
                                        CheckComment(session, comment);
                                    }
                                }

                                scriptBlocks = Utility.GetHtmlTagBodies(body, "script");
                                if (scriptBlocks != null)
                                {
                                    foreach (String s in scriptBlocks)
                                    {
                                        foreach (Match comments in Utility.GetJavascriptMultiLineComment(s))
                                        {
                                            comment = comments.ToString();
                                            CheckComment(session, comment);
                                        }
                                        foreach (Match comments in Utility.GetJavascriptSingleLineComment(s))
                                        {
                                            comment = comments.ToString();
                                            CheckComment(session, comment);
                                        }
                                    }
                                }
                            }

                            // Look at application/javascript responses
                            if (Utility.IsResponseJavascript(session))
                            {
                                foreach (Match comments in Utility.GetJavascriptMultiLineComment(body))
                                {
                                    comment = comments.ToString();
                                    if (comment != null)
                                    {
                                        CheckComment(session, comment);
                                    }
                                }
                                foreach (Match comments in Utility.GetJavascriptSingleLineComment(body))
                                {
                                    comment = comments.ToString();
                                    if (comment != null)
                                    {
                                        CheckComment(session, comment);
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