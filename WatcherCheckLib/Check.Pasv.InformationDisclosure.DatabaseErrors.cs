// WATCHER
//
// Check.Pasv.InformationDisclosure.DatabaseErrors.cs
// Checks for database error messages in the page content.
//
// Copyright (c) 2009 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Data;
using System.Text;
using System.Windows.Forms;
using Fiddler;

namespace CasabaSecurity.Web.Watcher.Checks
{
    /// <summary>
    /// Check for common error messages returned by databases, which may indicate SQL injection potential.
    /// </summary>
    public class CheckPasvInformationDisclosureDatabaseErrors : WatcherCheck
    {
        private string alertbody = "";
        private int findingnum;
        private StringCheckConfigPanel configpanel;
        private volatile List<string> wordlist = new List<string>();
        String[] defaultstrings = {"microsoft ole db provider for odbc drivers error", "[ODBC Informix driver][Informix]",
                                      "you have an error in your sql syntax; check the manual that corresponds to your mysql server version for the right syntax to use",
                                  "[Microsoft][ODBC Microsoft Access 97 Driver]", "[Microsoft][ODBC Driver Manager]",
                                  "[Microsoft][ODBC SQL Server Driver]", "Invalid column name",
                                    "You have an error in your SQL syntax near", "Unclosed quotation mark before the character string",
                                   "[SQL Server Driver][SQL Server]Line 1: Incorrect syntax near", "supplied argument is not a valid MySQL result resource",
                                    "Failed query:", "divide by zero", "You have an error in your SQL syntax", "SQL error message", 
                                    "MySQL error with query", "on MySQL result index", "Bad arguments to join() in", "Bad arguments to implode() in", "mysql_connect():",
                                  "Warning: mysql_query()", "ORA-", "unexpected end of SQL command", "SQL command not properly ended", "missing expression", 
                                  "Warning: pg_connect()", "Supplied argument is not a valid PostgreSQL result", "unexpected token \"END-OF-STATEMENT\"", 
                                  "internal error [IBM][CLI Driver][DB2/6000]"};

        public CheckPasvInformationDisclosureDatabaseErrors()
        {
            // Complies with OWASP ASVL 1 & 2 (DVR 8.9)
            StandardsCompliance =
                WatcherCheckStandardsCompliance.OwaspAppSecVerificationLevel1 |
                WatcherCheckStandardsCompliance.OwaspAppSecVerificationLevel2;
            
            //Setup Configuration Panel and initialize
            configpanel = new StringCheckConfigPanel(this);
            configpanel.Init(defaultstrings,"Database Error Strings:","Enter new Database Error Strings here:");
            UpdateWordList();
        }

        public override String GetName()
        {
            return "Information Disclosure - Check for common error messages returned by databases, which may indicate SQL injection potential.";
        }

        public override String GetDescription()
        {
            String desc = "This check looks for common error messages returned by database providers such as MSSQL, MySQL, and Oracle.  " +
                    "Even though these messages can sometimes be hidden in the " +
                    "HTML or comments, this check will search them out.  You can configure the list of common error messages " +
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

        private void AddAlert(Session session)
        {
            String name = "Database Error Message";
            String text =

                name +
                "\r\n\r\n" +
                "Risk: Informational\r\n\r\n" +
                "The response to the following request appeared to contain a database error message:\r\n\r\n" +
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