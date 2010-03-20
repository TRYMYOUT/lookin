// WATCHER
//
// Check.Pasv.Header.WeakAuth.cs
// Checks for weak auth protocols like Digest and Basic.
//
// Copyright (c) 2010 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Text;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Globalization;
using Fiddler;

namespace CasabaSecurity.Web.Watcher.Checks
{
    public class CheckPasvHeaderWeakAuth : WatcherCheck
    {
        // this list is cleared when the Clear button is clicked in the form.
        private volatile List<String> urls = new List<String>();
        [ThreadStatic] static private int findingnum;

        public override String GetName()
        {
            return "Header - Look for weak authentication protocols.";
        }

        public override String GetDescription()
        {
            String desc = "This check flags HTTP responses which request a weak authentication protocol such as Basic or Digest." +
                    "You will need to determine whether this would be considered a vulnerability in your organization.  " +
                    "Typically usage of these protocols are frowned upon even when used over secure SSL channels.";

            return desc;
        }

        private void AddAlert(Session session, String context)
        {
            string name = "Weak authorization method";
            findingnum++;
            string text =
                findingnum.ToString() + ") " +
                "The server issued a weak Basic or Digest authorization challenge:\r\n\r\n" +
                session.fullUrl +
                "\r\n\r\n" +
                "The context was:\r\n\r\n" +
                context;

            WatcherEngine.Results.Add(WatcherResultSeverity.Medium, session.id, session.fullUrl, name, text, StandardsCompliance, findingnum);
        }

        public override void Clear()
        {
            lock (urls)
            {
                urls = new List<String>();
            }
        }

        public override void Check(Session session, UtilityHtmlParser htmlparser)
        {
            bool authBasic = session.oResponse.headers.ExistsAndContains("WWW-Authenticate", "Basic");
            bool authDigest = session.oResponse.headers.ExistsAndContains("WWW-Authenticate", "Digest");
            string headers = session.oResponse.headers.ToString();
            //alertbody + "";
            findingnum = 0;

            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname))
            {
                if (session.responseCode == 401)
                {
                    if (authBasic || authDigest)
                    {
                        if (Utility.UrlNotInList(session.fullUrl, urls))
                        {
                            AddAlert(session, headers);
                        }
                    }
                }
            }
        }
    }
}