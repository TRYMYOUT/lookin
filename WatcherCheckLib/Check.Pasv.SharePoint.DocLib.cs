// WATCHER
//
// Check.Pasv.SharePoint.DocLib.cs
// Flags document library content that loads HTML.
//
// Copyright (c) 2009 Casaba Security, LLC
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
    public class CheckPasvSharePointDocLib : WatcherCheck
    {
        private int findingnum;
        private static String referrer;
        private static String doclibroot;

        public override String GetName()
        {
            return "(EXPERIMENTAL) SharePoint - Look for dangerous HTML content hosted in the Shared Document Library.";
        }

        public override String GetDescription()
        {
            String desc = "This check flags SharePoint document libraries which return HTML content " +
                    "without setting the Content-Disposition HTTP header.  Setting this header tells " +
                    "the Web browser to download the content rather than to parse and display it.  " +
                    "Without setting this header, users could upload malicious HTML content that would " +
                    "load and execute in a visitor's browser.";

            return desc;
        }

        private void AddAlert(Session session)
        {
            String root = String.Empty;
            if (!String.IsNullOrEmpty(referrer))
            {
                root = referrer;
            }
            else root = doclibroot;

            string name = "SharePoint insecure DocLib";
            findingnum++;
            string text =

                name +
                "\r\n\r\n" +
                "Risk: High\r\n\r\n" +
                findingnum.ToString() + ") " +
                "A doclib seems to be displaying HTML content at the following URL.  This could pose " +
                "a security risk if users are allowed to upload unmoderated content.  This finding will need " +
                "to be manually validated.\r\n\r\n" +
                session.fullUrl +
                "\r\n\r\nThe root of the DocLib is at:\r\n\r\n" +
                root;

            WatcherEngine.Results.Add(WatcherResultSeverity.Informational, session.id, session.url, name, text, StandardsCompliance, findingnum);
        }

        public override void Clear()
        {
        }

        public static bool IsDocLib(String body, Session session)
        {
            try
            {
                // TODO add more identifiers.
                String[] identifiers = { 
                                   "SharePoint.OpenDocuments.3",  // The OpenDocuments control used on doclib pages
                                   "onetidDoclibViewTbl0"        // The TABLE ID used in doclib pages
                                   };
                String docroot = String.Empty;

                // Try a few tricks to see if this might be a Sharepoint DocLib
                if (session.oRequest.headers.Exists("Referer"))
                {
                    referrer = session.oRequest.headers["Referer"];
                    Session referrerSession = WatcherEngine.Sessions.Find(FindReferrerInSessionList);
                    String referrerBody = Utility.GetResponseText(referrerSession);

                    foreach (String s in identifiers)
                    {
                        if (referrerBody.Contains(s))
                            return true;
                    }
                }

                else
                // If a referrer wasn't found, attempt to find the DocLib root folder.
                {
                    // Last index of a "/" - we're attempting to find the root folder.
                    int doclibrootIndex = session.fullUrl.LastIndexOf("/");
                    doclibroot = session.fullUrl.Substring(0, doclibrootIndex + 1);
                    doclibroot = System.Web.HttpUtility.UrlDecode(doclibroot);
                    Session docrootSession = WatcherEngine.Sessions.Find(FindDocLibRootInSessionList);

                    // Redirects are common to push clients to the main aspx page.
                    if (docrootSession.responseCode == 302 || docrootSession.responseCode == 301)
                    {
                        doclibroot = docrootSession.oResponse.headers["Location"];
                        doclibroot = System.Web.HttpUtility.UrlDecode(doclibroot);
                        docrootSession = WatcherEngine.Sessions.Find(FindDocLibRootInSessionList);
                    }
                    if (docrootSession != null)
                    {
                        docroot = Utility.GetResponseText(docrootSession);
                    }

                    foreach (String s in identifiers)
                    {
                        if (docroot.Contains(s))
                            return true;
                    }
                }
                return false;
            }
            catch (Exception)
            {
                return false;
            }

        }

        static bool FindReferrerInSessionList(Session session)
        {
            return (session.fullUrl == referrer);
        }
        static bool FindDocLibRootInSessionList(Session session)
        {
            return (System.Web.HttpUtility.UrlDecode(session.fullUrl) == doclibroot);
        }

        public override void Check(Session session, UtilityHtmlParser htmlparser)
        {
            findingnum = 0;

            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname))
            {
                if (session.responseCode == 200)
                {
                    if (Utility.IsResponseHtml(session))
                    {
                        if (session.oResponse.headers.Exists("MicrosoftSharePointTeamServices")) // Sharepoint response header
                        {
                            // Document Libraries don't have to be called "Shared Documents"
                            // and the response may not include SharePoint's MicrosoftSharePointTeamServices 
                            // HTTP header, so try some other things here to find out what's up.
                            if (IsDocLib(Utility.GetResponseText(session), session))
                            {
                                // Response doesn't include a "Content-Disposition: attachment" header.
                                if (!session.oResponse.headers.ExistsAndContains("Content-Disposition", "attachment"))
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
}