// WATCHER
//
// Check.Pasv.SSL.InsecureFormPost.cs
// Checks HTTPS pages that host HTTP forms.
//
// Copyright (c) 2010 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Text.RegularExpressions;
using Fiddler;

namespace CasabaSecurity.Web.Watcher.Checks
{
    public class CheckPasvSSLInsecureFormPost : WatcherCheck
    {
        [ThreadStatic] static private string alertbody = "";
        [ThreadStatic] static private int findingnum;

        public CheckPasvSSLInsecureFormPost()
        {
            CheckCategory = WatcherCheckCategory.SSL;
            LongName = "SSL - Look for insecure transition from HTTPS to HTTP during Form Post.";
            LongDescription = "This check identifies secure HTTPS pages that host insecure HTTP forms. The issue is that a secure page is transitioning to an insecure page when data is uploaded through a form. The user may think they're submitting data to a secure page when in fact they are not.";
            ShortName = "HTTPS to HTTP insecure transition in form post";
            ShortDescription = "The response to the following request over HTTPS included an HTTP form tag action attribute value:\r\n\r\n";
            Reference = "http://websecuritytool.codeplex.com/wikipage?title=Checks#ssl-insecure-transition-to-http";
            Recommendation = "Ensure sensitive data is only sent over secured HTTPS channels.";
        }

        private void AddAlert(Session session)
        {
            String name = ShortName;
            String text =
                ShortDescription +
                session.fullUrl +
                "\r\n\r\n" + 
                alertbody;

            WatcherEngine.Results.Add(WatcherResultSeverity.Medium, session.id, session.fullUrl, name, text, StandardsCompliance, findingnum, Reference);
        }

        private void AssembleAlert(String context)
        {
            findingnum++;
            alertbody = alertbody + 
                findingnum.ToString() + ") " +
                "The context was:\r\n\r\n" +
                context;
        }

        public override void Check(Session session, UtilityHtmlParser htmlparser)
        {
            String bod = null;
            String act = null;
            alertbody = "";
            findingnum = 0;

            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname))
            {
                if (session.responseCode == 200)
                {
                    if (session.isHTTPS)
                    {
                        if (Utility.IsResponseHtml(session))
                        {
                            bod = Utility.GetResponseText(session);
                            if (bod != null)
                            {
                                foreach (Match m in Utility.GetHtmlTags(bod, "form"))
                                {
                                    act = Utility.GetHtmlTagAttribute(m.ToString(), "action");
                                    if (act != null)
                                        if (act.Trim().ToLower().IndexOf("http://") == 0)
                                            AssembleAlert(m.ToString());
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
}