// WATCHER
//
// Check.Pasv.InformationDisclosure.InUrl.cs
// Checks for potentially sensitive information leaked in the URL.
//
// Copyright (c) 2010 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Web;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Windows.Forms;
using Fiddler;

namespace CasabaSecurity.Web.Watcher.Checks
{
    public class CheckPasvInformationDisclosureInURL : WatcherCheck
    {
        [ThreadStatic] static private string alertbody = "";
        [ThreadStatic] static private int findingnum;

        private StringCheckConfigPanel configpanel;
        private volatile List<string> wordlist = new List<string>();
        String[] defaultstrings = { "user", "username", "pass", "password", "token", "ticket", "session", "jsessionid", "sessionid" };

        public CheckPasvInformationDisclosureInURL()
        {
            // Complies with OWASP ASVL 2 (DVR 9.5)
            StandardsCompliance = WatcherCheckStandardsCompliance.OwaspAppSecVerificationLevel2;

            configpanel = new StringCheckConfigPanel(this);
            configpanel.Init(defaultstrings, "Sensitive URL Values:", "Enter new words to watch for here:");
            UpdateWordList();
        }

        public override String GetName()
        {
            return "Information Disclosure - Look for sensitive information passed through URL parameters.";
        }

        public override String GetDescription()
        {
            String desc = "This check looks for string patterns to identify sensitive information leaked in the URL.  " +
                    "This can violate PCI and most organizational compliance policies.  You can configure the list of strings below " +
                    "to add or remove values specific to your environment.\r\n\r\n" +
                    "In addition this check will find credit card numbers, SSN's, and email addresses.";

            return desc;
        }

        /// <summary>
        /// TODO: Change to informational when leaks occur in same domain, medium when going offsite.
        /// </summary>
        /// <param name="watcher"></param>
        /// <param name="session"></param>
        /// <param name="param"></param>
        /// <param name="context"></param>
        private void AddAlert(Session session, bool equal)
        {
            string name = "Information leak in URL parameter";
            if (!equal)
            {
                string text =
                    "The following request may have leaked a potentially sensitive parameter in a URL parameter:\r\n\r\n" +
                    session.fullUrl +
                    "\r\n\r\n" +
                    alertbody;

                WatcherEngine.Results.Add(WatcherResultSeverity.Medium, session.id, session.fullUrl, name, text, StandardsCompliance, findingnum);
            }
            else
            {
                string text =
                    "The following request may have leaked a potentially sensitive parameter in a URL parameter" +
                    "(even though protected by https it will still be in URL history):\r\n\r\n" +
                    session.fullUrl +
                    "\r\n\r\n" +
                    alertbody;

                WatcherEngine.Results.Add(WatcherResultSeverity.Low, session.id, session.fullUrl, name, text, StandardsCompliance);
            }
        }

        public override System.Windows.Forms.Panel GetConfigPanel()
        {
            System.Windows.Forms.Panel panel = new System.Windows.Forms.Panel();
            panel.Dock = System.Windows.Forms.DockStyle.Fill;
            configpanel.Dock = System.Windows.Forms.DockStyle.Fill;
            panel.Controls.Add(configpanel);
            return panel;
        }

        private void AssembleAlert(String param, String value, String subject)
        {
            // If the value is null that means we don't have to do name=value
            // style reporting.
            if (!String.IsNullOrEmpty(value))
            {
                value = String.Concat("=", value);
            }

            findingnum++;
            alertbody = alertbody + findingnum.ToString() + ") " +
                "A(n) '" + subject + "' seems to have been found with the value:\r\n\r\n" +
                param + value +
                "\r\n\r\n";
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

        private void LookForSensitiveInformation(String parameter, String rex, String value)
        {
            // Get out of here if value is null, we don't want to report on empty values.
            if (String.IsNullOrEmpty(value)) return;

            // nulls shouldn't get here but just in case
            if (parameter != null && Utility.IsEmailAddress(parameter))
            {
                AssembleAlert(parameter, null, "email address");
            }

            // nulls shouldn't get here but just in case
            if (parameter != null && Utility.IsCreditCard(parameter))
            {
                AssembleAlert(parameter, null, "credit card number");
            }

            // nulls shouldn't get here but just in case
            if (parameter != null && Utility.IsUsSSN(parameter))
            {
                AssembleAlert(parameter, null, "US Social Security number");
            }
            List<string> words;
            lock (wordlist)
            {
                words = new List<string>(wordlist);
            }
            foreach (String word in words)
            {
                if (parameter.ToLower() == word.ToLower())
                    AssembleAlert(parameter, value, word.ToLower());
            }
        }

        public override void Check(Session session, UtilityHtmlParser htmlparser)
        {
            NameValueCollection parameters = null;
            String value = String.Empty;

            alertbody = String.Empty;
            findingnum = 0;

            // update this array with name values you want to identify
            string rex = null;

            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname) || WatcherEngine.Configuration.IsTrustedDomain(session.hostname))
            {
                if (session.url != null)
                {

                    rex = session.url;
                    //string refername = Utility.GetUriDomainName(rex);
                    //string hostname = session.hostname;


                    // if have query string
                    if (rex.IndexOf("?") > 0)
                    {
                        parameters = HttpUtility.ParseQueryString(rex.Substring(rex.IndexOf("?") + 1));

                        if (parameters != null && parameters.Keys.Count > 0)
                        {
                            //IEnumerator myenumerator = parameters.GetEnumerator();
                            foreach (String param in parameters.AllKeys)
                            {
                                try
                                {
                                    if (String.IsNullOrEmpty(param))
                                    {
                                        throw new NullReferenceException();
                                    }
                                    else 
                                    {
                                        value = parameters.Get(param);
                                        LookForSensitiveInformation(param, rex, value);
                                        LookForSensitiveInformation(parameters[param], rex, value);
                                    }
                                }
                                catch (NullReferenceException)
                                {
                                    // means that a parameter value was null, so let's check the parameter names instead
                                    // e.g. it might be a URL like:
                                    // http://www.nottrusted.com/?abc&def&ghi
                                    // Instead of the expected name=value pairs like:
                                    // http://www.nottrusted.com/?a=b&c=d&e=f
                                    //
                                    // TODO: We need to implement similar logic throughout Watcher wherever query string params are parsed
                                    string p = parameters.ToString().ToLower();
                                    LookForSensitiveInformation(p, rex, value);
                                }
                            }
                            if (!String.IsNullOrEmpty(alertbody))
                            {
                                AddAlert(session, session.isHTTPS);
                            }
                        }
                    }
                }
            }
        }
    }
}