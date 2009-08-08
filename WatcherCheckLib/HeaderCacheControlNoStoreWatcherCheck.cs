using System;
using System.IO;
using Fiddler;

namespace WatcherCheckLib
{
    /// <summary>
    /// Checks that the cache-control header is set to no-store (which is good) and reports an informational finding.
    /// 
    /// TODO: Roll this up into the HeaderCacheControlInsecureWatcherCheck as a 'good' finding.
    /// </summary>
    public class HeaderCacheControlNoStoreWatcherCheck : WatcherEngine.WatcherCheck
    {

        public override String GetName()
        {
            return "Checks that the cache-control header is set to no-store (which is good) and reports an informational finding.";
        }

        private void AddAlert(WatcherEngine.Watcher watcher, Session session, String header)
        {
            string name = "Cache-Control Header No Store";
            string text =

                name +
                "\r\n\r\n" +
                "Risk: Informational\r\n\r\n" +
                "The response to the following request included a Cache-Control header value of no-store:\r\n\r\n" +
                session.url +
                "\r\n\r\n" +
                "The Cache-Control header returned was:\r\n\r\n" +
                header;

            watcher.AddAlert(WatcherEngine.WatcherCheck.Informational, session.id, session.url, name, text);
        }

        public override void Check(WatcherEngine.Watcher watcher, Session session)
        {
            String pa = null;
            String cc = null;

            if (watcher.IsOriginDomain(session.hostname))
            {
                if (session.responseCode == 200)
                {
                    if (!session.HTTPMethodIs("CONNECT"))
                    {
                        if (session.isHTTPS)
                        {
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

                                        if (!pa.EndsWith(".jpg") && !pa.EndsWith(".gif") && !pa.EndsWith(".png") && !pa.EndsWith(".css") && !pa.EndsWith(".js"))
                                        {
                                            if (session.oResponse.headers.Exists("cache-control"))
                                                if ((cc = session.oResponse.headers["cache-control"]).Trim().ToLower() == "no-store")
                                                    AddAlert(watcher, session, cc);
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
}