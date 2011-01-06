// WATCHER
//
// Check.Pasv.Javascript.DomainLowering.cs
// Checks for document.domain lowering.
//
// Copyright (c) 2010 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Text.RegularExpressions;
using Fiddler;
using System.Diagnostics;

namespace CasabaSecurity.Web.Watcher.Checks
{
    //
    // Domain lowering is a method commonly used for sharing functionality across subdomains of a site. 
    // For example, when sub.foo.bar wants to access data or functions in sub2.foo.bar, it can 'lower' 
    // the document.domain property to foo.bar in javascript. This will create a cross-domain scenario 
    // where all subdomains of foo.bar can communicate freely.
    //
    // Limitations: This check does simple signature matching, looking for document.com = "value" in 
    // javascript.  It does not have a javascript interpreter available, so may fail to catch cases 
    // where document.domain = variable, although we can try to catch those cases too.
    //
    public class CheckPasvJavascriptDomainLowering : WatcherCheck
    {

        public CheckPasvJavascriptDomainLowering()
        {
            CheckCategory = WatcherCheckCategory.JavaScript;
            LongName = "Javascript - Examine javascript code document.domain lowering logic.";
            LongDescription = "Domain lowering is a method commonly used for sharing functionality across subdomains of a site. For example, when sub.foo.bar wants to access data or functions in sub2.foo.bar, it can 'lower' the document.domain property to foo.bar in javascript. This will create a cross-domain scenario where all subdomains of foo.bar can communicate freely.";
            ShortName = "Javascript domain lowering";
            ShortDescription = "The page at the following URL appears to contain javascript domain lowering logic:\r\n\r\n";
            Reference = "http://websecuritytool.codeplex.com/wikipage?title=Checks#javascript-domain-lowering";
            Recommendation = "Avoid domain lowering.";
        }

        private void AddAlert(Session session, String context)
        {
            String name = ShortName;
            String text =

                ShortDescription +
                session.fullUrl +
                "\r\n\r\n" +
                "The domain was lowered from " + session.hostname + " to " + context + "\r\n\r\n";

            WatcherEngine.Results.Add(WatcherResultSeverity.Low, session.id, session.fullUrl, name, text, StandardsCompliance, 1, Reference);
        }

        // TODO: Attempt to handle the case where document.domain = variable
        // by searching for the variable assignment.
        private void CheckDomainLowering(Session session, String input)
        {
            // Get the document.domain = "string" part from the javascript
            string documentDomain = string.Empty;
            string match = string.Empty;
            
            try 
            {
                if (!String.IsNullOrEmpty(input))
                {
                    match = Regex.Match(input, @"document\.domain\s*=\s*['""].*['""]", RegexOptions.Multiline).Value;
                }
            } 
            catch (ArgumentException e) 
            {
                // Syntax error in the regular expression
                Trace.TraceError("Error: ArgumentException: {0}", e.Message);
            }

            // Not the intended use of GetHtmlTagAttribute but it works
            documentDomain = Utility.GetHtmlTagAttribute(match, "document.domain");

            // The origin domain, either configured or assumed from the response.
            string originDomain = string.Empty;
            // An array containing the labels from the FQDN.
            string[] originDomainLabels = {};

            if (String.IsNullOrEmpty(WatcherEngine.Configuration.OriginDomain))
            {
                originDomain = session.hostname;
            }
            else
            {
                originDomain = WatcherEngine.Configuration.OriginDomain;
            }
            
            // split origin domain name into sub-domains
            originDomainLabels = originDomain.Split('.');            
            
            // Assuming hostname is www.foo.bar, split domain name into subdomains
            string[] documentDomainLabels = documentDomain.Split('.');


            // Domain lowering should have fewer sub-domains
            if (documentDomainLabels.Length > 0 && originDomainLabels.Length > documentDomainLabels.Length)
            {
                // and those domain labels should match the right most domain labels of the origin domain name
                // e.g. does bar == bar and does foo == foo?
                for (int x = 1; x <= documentDomainLabels.Length; ++x)
                {
                    // does sub-domain match?
                    if (documentDomainLabels[documentDomainLabels.Length - x] != originDomainLabels[originDomainLabels.Length - x])
                    {
                        // domain name label doesn't match, so something else is going on, maybe an error in what
                        // the HTTP page is producing.
                        // 
                        return;
                    }
                }
                // document.domain labels were fewer, and did match the origin
                AddAlert(session, documentDomain);
            }
        }

        public override void Check(Session session, UtilityHtmlParser htmlparser)
        {
            String[] bods = null;
            String body = null;

            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname))
            {
                if (session.responseCode == 200)
                {
                    if (Utility.IsResponseHtml(session) || Utility.IsResponseJavascript(session))
                    {
                        body = Utility.GetResponseText(session);
                        if (body != null)
                        {
                            if (Utility.IsResponseHtml(session))
                            {
                                bods = Utility.GetHtmlTagBodies(body, "script");
                                if (bods != null)
                                    foreach (String b in bods)
                                        CheckDomainLowering(session, b);
                            }

                            if (Utility.IsResponseJavascript(session))
                                CheckDomainLowering(session, body);
                        }
                    }
                }
            }
        }
    }
}