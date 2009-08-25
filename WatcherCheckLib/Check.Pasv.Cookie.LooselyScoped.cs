// WATCHER
//
// Check.Pasv.Cookie.LooselyScoped.cs
// Checks for cookies that are loosely scoped outside their origin domain.
//
// Copyright (c) 2009 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Collections;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Windows.Forms;
using Fiddler;

namespace CasabaSecurity.Web.Watcher.Checks
{
    public class CheckPasvCookieLooselyScoped : WatcherCheck
    {
        private static Hashtable cookietable = new Hashtable();
        private static bool filter = true;
        private CookieCheckConfigPanel configpanel;
        private string alertbody;
        private int findingnum;
        private List<String> wordlist = new List<string>();

        public CheckPasvCookieLooselyScoped()
        {
            configpanel = new CookieCheckConfigPanel(this);
            configpanel.Init();
        }

        public override String GetName()
        {
            return "Cookie - Look for cookies with loosely scoped domain restrictions.";
        }

        public override String GetDescription()
        {
            String desc = "Cookies can be scoped by domain or path.  This check is only concerned with domain scope." +
                    "The domain scope applied to a cookie determines which domains can access it.  For example, " +
                    "a cookie can be scoped strictly to a subdomain e.g. www.nottrusted.com, or loosely scoped to " +
                    "a parent domain e.g. nottrusted.com.  In the latter case, any subdomain of nottrusted.com can access the cookie" +
                    "Loosely scoped cookies are common in mega-applications like google.com and live.com.\r\n\r\n" +
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

        private void AddAlert(Session session, String org)
        {
            String name = "Cookie's domain was loosely scoped";
            String text =

                name +
                "\r\n\r\n" +
                "Risk: Medium\r\n\r\n" +
                "The response included a Set-Cookie header that specified a loosely scoped domain:\r\n\r\n" +
                session.url +
                "\r\n\r\n" +
                "The origin domain used for comparison was:\r\n\r\n" +
                org +
                "\r\n\r\n" +
                "The cookie(s) returned were:\r\n\r\n" +
                alertbody;

            WatcherEngine.Results.Add(WatcherResultSeverity.Medium, session.id, session.url, name, text, StandardsCompliance, findingnum);
        }

        public override void Check(Session session, UtilityHtmlParser htmlparser)
        {
            String[] dparts = null;
            String[] oparts = null;
            String cookie = null;
            String org = null;
            String dom = null;
            bool flag = false;
            List<string> cookies;
            lock (wordlist)
            {
                cookies = new List<string>(wordlist);
            }

            alertbody = "";
            findingnum = 0;

            String filterstate = configpanel.GetFilterState();
            filter = configpanel.enablefiltercheckBox.Checked;

            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname))
            {
                if (session.responseCode == 200)
                {
                    org = WatcherEngine.Configuration.OriginDomain;

                    //TODO: Check seems wrong if OriginDomain can accept regular expressions!!!!
                    if (org != null && org.Length > 0 && org.IndexOf("*") < 0)
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
                                        string cookiename = cookie.Split('=')[0];
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
                                        if (cookieinlist)
                                        {
                                            // extract 'domain=domain_name' in cookie
                                            Match m = Regex.Match(cookie, "(D|d)omain\\s*?=\\s*?[a-zA-Z0-9\\.]+");

                                            if (m.Success)
                                            {
                                                // remove "domain=" part
                                                dom = Regex.Replace(m.ToString(), "(D|d)omain\\s*?=", "").Trim().TrimStart('.');

                                                // if have domain name
                                                if (dom != null && dom.Length > 0)
                                                {
                                                    // split domain name into sub-domains
                                                    dparts = dom.Split('.');
                                                    // split origin domain name into sub-domains
                                                    oparts = org.Split('.');

                                                    // loosely scoped domain name should have fewer sub-domains
                                                    if (dparts.Length > 0 && oparts.Length > dparts.Length)
                                                    {
                                                        // and those sub-domains should match the right most sub-domains of the origin domain name
                                                        for (int x = 1; x <= dparts.Length; ++x)
                                                        {
                                                            // does sub-domain match?
                                                            if (dparts[dparts.Length - x] != oparts[oparts.Length - x])
                                                            {
                                                                // no
                                                                flag = true;
                                                                break;
                                                            }
                                                        }

                                                        // right-most sub-domains did match
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
                                    }
                                }
                                if (!String.IsNullOrEmpty(alertbody))
                                {
                                    AddAlert(session, org);
                                }
                            }
                        }
                    }       
                }
            }
        }
    }
}