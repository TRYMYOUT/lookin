// WATCHER
//
// Check.Pasv.Cookie.HttpOnly.cs
// Checks that HTTPOnly flag is set on cookies.
//
// Copyright (c) 2009 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Text.RegularExpressions;
using System.Collections;
using System.Collections.Generic;
using System.Windows.Forms;
using Fiddler;
using CasabaSecurity.Web.Watcher;

namespace CasabaSecurity.Web.Watcher.Checks
{
    /// <summary>
    /// Look for instances where the HTTPOnly cookie flag is not being set.
    /// </summary>
    public class CheckPasvCookieHTTPOnly : WatcherCheck
    {
        private static Hashtable cookietable = new Hashtable();
        private static bool filter = true;
        private CookieCheckConfigPanel configpanel;
        private string alertbody;
        private int findingnum;
        private volatile List<String> wordlist = new List<string>();

        public CheckPasvCookieHTTPOnly()
        {
            // Complies with OWASP ASVL 2 (DVR 11.1)
            StandardsCompliance = WatcherCheckStandardsCompliance.OwaspAppSecVerificationLevel2;

            configpanel = new CookieCheckConfigPanel(this);
            configpanel.Init();
        }

        public override String GetName()
        {
            return "Cookie - Look for instances where the HTTPOnly cookie flag is not being set.";
        }

        public override String GetDescription()
        {
            String desc = "This check looks for cookies that don't have the HTTPOnly flag set.  " +
                    "When a cookie is set with the HTTPOnly flag, it instructs the browser that the cookie " +
                    "can only be accessed by the server.  In other words, client-side script " +
                    "is forbidden from accessing the cookie.  This is an important security protection " +
                    "for session cookies and other sensitive cookies, but less important for others.\r\n\r\n" +
                    "Because Watcher can't distinguish between the important and unimportant " +
                    "cookies, you can configure an inclusive or exclusive list of cookie names to watch below.";

            return desc;
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
            List<String> list = new List<string>();
            if (configpanel.cookiechecklistBox.Items.Count > 0)
            {
                foreach (ListViewItem item in configpanel.cookiechecklistBox.Items)
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
            String name = "Set-Cookie HTTPOnly Attribute Not Set";
            String text =

                name +
                "\r\n\r\n" +
                "Risk: Medium\r\n\r\n" +
                "The response included a Set-Cookie header that did not include the HTTPOnly attribute:\r\n\r\n" +
                session.url +
                "\r\n\r\n" +
                "The cookie(s) returned were:\r\n\r\n" +
                alertbody;

            WatcherEngine.Results.Add(WatcherResultSeverity.Medium, session.id, session.url, name, text, StandardsCompliance, findingnum);
        }

        public override void Check(Session session, UtilityHtmlParser htmlparser)
        {
            String[] parts = null;
            String cookie = null;
            bool flag = false;
            List<string> cookielist;
            List<string> cookies;
            lock (wordlist)
            {
                cookies = new List<string>(wordlist);
            }
            String filterstate = configpanel.GetFilterState();

            alertbody = "";
            findingnum = 0;
            filter = configpanel.enablefiltercheckBox.Checked;

            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname))
            {
                if (session.responseCode == 200)
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
                                            if (part.Trim().ToLower() == "httponly")
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
                                                    cookielist = (List<String>)cookietable[session.hostname];
                                                    if (!cookietable.ContainsKey(session.hostname))
                                                    {
                                                        List<String> newcookielist = new List<String>();
                                                        newcookielist.Add(cookie.Split('=')[0]);
                                                        cookietable.Add(session.hostname, newcookielist);
                                                        findingnum++;
                                                        alertbody = alertbody + findingnum.ToString() + ") " + cookie + "\r\n\r\n";
                                                    }
                                                    else if (!cookielist.Contains(cookie.Split('=')[0]))
                                                    {
                                                        cookielist.Add(cookie.Split('=')[0]);
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