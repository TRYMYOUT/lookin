// WATCHER
//
// Check.Pasv.Header.Security.cs
// Checks for HTTP responses for the X-FRAME-OPTIONS header and setting.
//
// Copyright (c) 2010 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Text.RegularExpressions;
using Fiddler;

namespace CasabaSecurity.Web.Watcher.Checks
{
    /// <summary>
    /// Checks for private IP addresses in the HTTP headers. 
    /// </summary>
    public class CheckPasvHeaderInternalIp : WatcherCheck
    {

        public CheckPasvHeaderInternalIp()
        {
            CheckCategory = WatcherCheckCategory.Header;
            LongName = "Header - Check HTTP response headers for private IP address disclosure.";
            LongDescription = "This check applies a regular expression to the entire set of HTTP headers to match private IP addresses";
            ShortName = "Private IP address disclosure.";
            ShortDescription = "The response to the following request included a private IP address in the HTTP headers:\r\n\r\n";
            Reference = "http://websecuritytool.codeplex.com/wikipage?title=Checks#private-ip-address";
            Recommendation = "Configure the Web server to prevent private IP address disclosure.";
        }

        private void AddAlert(Session session, String header, String ip)
        {
            string name = ShortName;
            string url = session.fullUrl.Split('?')[0];
            string text =
                ShortDescription +
                url +
                "\r\n\r\n" +
                "HTTP Header: " + header + "\r\n" +
                "Private IP Address: " + ip;

            WatcherEngine.Results.Add(WatcherResultSeverity.Low, session.id, session.fullUrl, name, text, StandardsCompliance, 1, Reference);
        }

        public override void Check(Session session)
        {
            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname))
            {

                string resultString = null;
                foreach(HTTPHeaderItem header in session.oResponse.headers)
                {
                    try
                    {
                        resultString = Regex.Match(header.Value, @"(10\.\d\.\d\.\d)|(172\.1[6-9]\.\d\.\d)|(172\.2[0-9]\.\d\.\d)|(172\.3[0-1]\.\d\.\d)|(192\.168\.\d\.\d)").Value;
                    }
                    catch (ArgumentException ex)
                    {
                        // Syntax error in the regular expression
                    }
                    if (!String.IsNullOrEmpty(resultString))
                    {
                        AddAlert(session, header.Name, resultString);
                    }

                }

            }
        }
    }
}