// WATCHER
//
// Check.Pasv.Cookie.Secure.cs
// Checks that cookies set over SSL have the 'secure' flag set..
//
// Copyright (c) 2010 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Collections;
using System.Collections.Generic;
using System.Windows.Forms;
using Fiddler;

namespace CasabaSecurity.Web.Watcher.Checks
{
    /// <summary>
    /// Look for instances where the secure cookie flag is not being set on HTTPS connections that Set-cookie.
    /// </summary>
    public class CheckPasvCookieSecure : WatcherCheck
    {
        private volatile static Hashtable cookietable = new Hashtable();
        private static bool filter = true;
        private CookieCheckConfigPanel configpanel;
        [ThreadStatic] static private string alertbody = "";
        [ThreadStatic] static private int findingnum;
        private volatile List<String> wordlist = new List<string>();

        public CheckPasvCookieSecure()
        {
            // Complies with OWASP ASVL 2 (DVR 11.2)
            StandardsCompliance = WatcherCheckStandardsCompliance.OwaspAppSecVerificationLevel2;

            configpanel = new CookieCheckConfigPanel(this);
            configpanel.Init();
            configpanel.enablefiltercheckBox.Visible = false; //Hack requested to enable filtering always

            CheckCategory = WatcherCheckCategory.Cookie;
            LongName = "Cookie - Look for cookies without the \"secure\" attribute.";
            LongDescription = "This check identifes cookies set over SSL which don't set the 'secure' flag. When a cookie is set with the 'secure' flag, it instructs the browser that the cookie can only be accessed over secure SSL channels. This is an important security protection for session cookies and other sensitive cookies that should never leak or be passed over an unencrypted channel.  Because Watcher can't distinguish between the important and unimportant cookies, you can configure an inclusive or exclusive list of cookie names to watch.";
            ShortName = "Cookie's secure flag was not set";
            ShortDescription = "A response over TLS/SSL included a Set-Cookie header that did not include the secure attribute:\r\n\r\n";
            Reference = "http://websecuritytool.codeplex.com/wikipage?title=Checks#cookie-not-setting-secure-flag";
            Recommendation = "Always set the 'secure' flag for session cookies and other sensitive cookies that should never be sent over unencrypted channels.";
        }

        public override void Clear()
        {
            lock (cookietable)
            {
                cookietable = new Hashtable();
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

        public override void UpdateWordList()
        {
            if (configpanel.cookiechecklistBox.Items.Count > 0)
            {
                List<String> list = new List<string>();
                foreach (ListViewItem item in configpanel.cookiechecklistBox.Items)
                {
                    list.Add(item.Text);
                }
                lock (wordlist)
                {
                    wordlist = list;
                }
            }
        }

        private void AddAlert(Session session)
        {
            String name = ShortName;
            String text =
                ShortDescription +
                session.fullUrl +
                "\r\n\r\n" +
                "The cookie(s) returned were:\r\n\r\n" +
                alertbody;

            WatcherEngine.Results.Add(WatcherResultSeverity.Medium, session.id, session.fullUrl, name, text, StandardsCompliance, findingnum, Reference);
        }

        public override void Check(Session session)
        {
            String[] parts = null;
            String cookie = null;
            bool flag = false;
            List<string> cookies;
            lock (wordlist)
            {
                cookies = new List<string>(wordlist);
            }
            String filterstate = configpanel.GetFilterState();

            alertbody = "";
            findingnum = 0;
            //filter = configpanel.enablefiltercheckBox.Checked;
            filter = true; //Hack requested to always enable filtering

            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname))
            {
                if (session.responseCode == 200)
                {
                    if (session.isHTTPS)
                    {
                        if (session.oResponse.headers.Exists("set-cookie"))
                        {
                            foreach (HTTPHeaderItem c in session.oResponse.headers)
                            {
                                if (c.Name.ToLower() == "set-cookie")
                                {
                                    cookie = c.Value;

                                    if (cookie != null && cookie.Length > 0)
                                    {
                                        parts = cookie.Split(';');
                                        string cookiename = parts[0];
                                        cookiename = cookiename.Split('=')[0];
                                        bool cookieinlist;
                                        //check filter
                                        if (filterstate == "Inclusive Filter" && cookies.Count > 0)
                                        {
                                            //cookie should be in list
                                            cookieinlist = cookies.Contains(cookiename);
                                        }
                                        else
                                        {
                                            //cookie should not be in list
                                            cookieinlist = !cookies.Contains(cookiename);
                                        }
                                        if (parts != null && parts.Length > 0 && cookieinlist)
                                        {
                                            flag = false;

                                            foreach (String part in parts)
                                            {
                                                if (part.Trim().ToLower() == "secure")
                                                {
                                                    flag = true;
                                                    break;
                                                }
                                            }

                                            if (!flag)
                                            {
                                                if (filter)
                                                {
                                                    lock (cookietable)
                                                    {
                                                        if (!cookietable.ContainsKey(session.hostname))
                                                        {
                                                            List<String> cookielist = new List<String>();
                                                            cookielist.Add(cookie.Split('=')[0]);
                                                            cookietable.Add(session.hostname, cookielist);
                                                            findingnum++;
                                                            alertbody = alertbody + findingnum.ToString() + ") " + cookie + "\r\n\r\n";
                                                        }
                                                        else if (!((List<String>)cookietable[session.hostname]).Contains(cookie.Split('=')[0]))
                                                        {
                                                            ((List<String>)cookietable[session.hostname]).Add(cookie.Split('=')[0]);
                                                            findingnum++;
                                                            alertbody = alertbody + findingnum.ToString() + ") " + cookie + "\r\n\r\n";
                                                        }
                                                    }
                                                }
                                                else
                                                {
                                                    findingnum++;
                                                    alertbody = alertbody + findingnum.ToString() + ") " + cookie + "\r\n\r\n";
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