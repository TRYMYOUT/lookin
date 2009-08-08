// WATCHER
//
// Check.Pasv.InformationDisclosure.DebugErrors.cs
// Checks for web server debug error messages in the page content.
//
// Copyright (c) 2009 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using Fiddler;
using System.Windows.Forms;

namespace CasabaSecurity.Web.Watcher.Checks
{
    /// <summary>
    /// Check for common debugging type error messages returned from platforms such as ASP.NET and IIS.  This may indicate
    /// information disclosure or configuration issues.
    /// </summary>
    public class CheckPasvInformationDisclosureDebugErrors : WatcherCheck
    {
        private string alertbody = "";
        private int findingnum;
        private StringCheckConfigPanel configpanel;
        private volatile List<string> wordlist = new List<string>();
        String[] defaultstrings = {"Error Occurred While Processing Request", "Internal Server Error", "test page for apache",
                                      "failed to open stream: HTTP request failed!", "Parse error: parse error, unexpected T_VARIABLE",
                                      "The script whose uid is", "PHP Parse error", "PHP Warning", "PHP Error", "Warning: Cannot modify header information - headers already sent",
                                      "mysqli error is", "404 SC_NOT_FOUND", "ASP.NET_SessionId", "servlet error:", "Under construction", "Welcome to Windows 2000 Internet Services",
                                      "welcome to iis 4.0", "Warning: Supplied argument is not a valid File-Handle resource", "Warning: Division by zero in",
                                      "Warning: SAFE MODE Restriction in effect.", "Error Message : Error loading required libraries.", 
                                      "Fatal error: Call to undefined function", "access denied for user", "incorrect syntax near", 
                                      "Unclosed quotation mark before the character string", "There seems to have been a problem with the"};

        public CheckPasvInformationDisclosureDebugErrors()
        {
            // Complies with OWASP ASVL 1 & 2 (DVR 8.9)
            StandardsCompliance = 
                WatcherCheckStandardsCompliance.OwaspAppSecVerificationLevel1 | 
                WatcherCheckStandardsCompliance.OwaspAppSecVerificationLevel2;

            //Setup Configuration Panel and initialize
            configpanel = new StringCheckConfigPanel(this);
            configpanel.Init(defaultstrings, "Database Error Strings:", "Enter new Database Error Strings here:");
            UpdateWordList();
        }

        public override String GetName()
        {
            return "Information Disclosure - Check for common debugging type error messages returned from platforms such as ASP.NET and IIS.";
        }

        public override String GetDescription()
        {
            String desc = "This check looks for common error messages returned by Web Servers such as IIS and Apache.  " +
                    "Even though these messages can sometimes be hidden in the " +
                    "HTML or comments, this check will search them out.You can configure the list of common debug messages " +
                    "to look for below.";

            return desc;
        }

        public override System.Windows.Forms.Panel GetConfigPanel()
        {
            System.Windows.Forms.Panel panel = new System.Windows.Forms.Panel();
            panel.Dock = System.Windows.Forms.DockStyle.Fill;
            configpanel.Dock = System.Windows.Forms.DockStyle.Fill;
            panel.Controls.Add(configpanel);
            return panel;
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

        private void AddAlert(Session session)
        {
            String name = "Debug Error Message";
            String text =

                name +
                "\r\n\r\n" +
                "Risk: Informational\r\n\r\n" +
                "The response to the following request appeared to contain debugging information:\r\n\r\n" +
                session.url +
                "\r\n\r\n" +
                alertbody;

            WatcherEngine.Results.Add(WatcherResultSeverity.Informational, session.id, session.url, name, text, StandardsCompliance, findingnum);
        }

        private void AssembleAlert(String errormsg)
        {
            findingnum++;
            alertbody = alertbody + findingnum.ToString() +
                ") The context was: " +
                errormsg +
                "\r\n\r\n";
        }

        public override void Check(Session session, UtilityHtmlParser htmlparser)
        {
            String bod = null;
            alertbody = "";
            findingnum = 0;

            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname))
            {
                if (session.responseCode == 200)
                {
                    if (Utility.IsResponseHtml(session))
                    {
                        bod = Utility.GetResponseText(session);
                        if (bod != null)
                        {
                            //bod = bod.ToLower();
                            List<string> errorMessages;
                            lock (wordlist)
                            {
                                errorMessages = new List<string>(wordlist);
                            }
                            foreach (String errormessage in errorMessages)
                                if (bod.Contains(errormessage))
                                    AssembleAlert(errormessage);
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