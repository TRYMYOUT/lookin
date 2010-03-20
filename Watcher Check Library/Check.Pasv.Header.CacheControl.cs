// WATCHER
//
// Check.Pasv.Header.CacheControl.cs
// Checks SSL pages that set the cache-control header to a weak value.
//
// Copyright (c) 2010 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.IO;
using Fiddler;

namespace CasabaSecurity.Web.Watcher.Checks
{
    /// <summary>
    /// Check that cache-control HTTP header is set to the 'no-store' value.  This check looks only at SSL exchanges and assumes that 
    /// all data would be confidential and require a no-store, rather than the less secure cache directives such as no-cache.
    /// </summary>
    public class CheckPasvHeaderCacheControl : WatcherCheck
    {
        [ThreadStatic] static private int findingnum;

        public override String GetName()
        {
            return "Header - Check that cache-control HTTP header is set to the 'no-store' value.";
        }

        public override String GetDescription()
        {
            String desc = "Even in secure SSL channels sensitive data could be stored by intermediary proxies and " +
                    "SSL terminators.  To direct such proxies from storing data, the 'no-store' Cache-Control header  " +
                    "should be specified.  This check will flag all SSL responses which don't set this value.\r\n\r\n" +
                    "False positives are likey with this as the check doesn't have a good way to determine what's truly " +
                    "sensitive data and what's not. See http://palisade.plynt.com/issues/2008Jul/cache-control-attributes/ for more details.";

            return desc;
        }

        private void AddAlert(Session session, String header)
        {
            string name = "Insecure Cache-Control header";
            findingnum++;
            string text =
                "The response to the following request included a potentially insecure Cache-Control header:\r\n\r\n" +
                session.fullUrl +
                "\r\n\r\n" +
                findingnum.ToString() + ") " +
                "The Cache-Control header returned was:\r\n\r\n" +
                header;


            WatcherEngine.Results.Add(WatcherResultSeverity.Low, session.id, session.fullUrl, name, text, StandardsCompliance, findingnum);
        }

        public override void Check(Session session, UtilityHtmlParser htmlparser)
        {
            String pa = null;
            String cc = null;
            findingnum = 0;

            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname))
            {
                if (session.responseCode == 200 || session.responseCode == 401)
                {
                    if (session.isHTTPS && session.responseBodyBytes.Length > 0)
                    {
                        // if content type does not being w/ "image/"
                        if (!Utility.IsResponseContentType(session, "image/"))
                        {
                            pa = session.PathAndQuery;

                            if (pa != null)
                            {
                                if (pa.IndexOf("?") > 0)
                                    pa = pa.Substring(0, pa.IndexOf("?"));

                                pa = Path.GetFileName(pa);
                                if (pa != null)
                                {
                                    pa = pa.ToLower();

                                    // and file does not end with jpg, gif or png
                                    if (!pa.EndsWith(".jpg") && !pa.EndsWith(".gif") && !pa.EndsWith(".png") && !pa.EndsWith(".css") && !pa.EndsWith(".js"))
                                    {
                                        if (session.oResponse.headers.Exists("cache-control"))
                                        {
                                            cc = session.oResponse.headers["cache-control"].Trim().ToLower();
                                            if (!cc.Contains("no-store"))
                                                AddAlert(session, cc);
                                        }
                                        else
                                            AddAlert(session, "No Cache-Control header returned. This may be insecure.");
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}