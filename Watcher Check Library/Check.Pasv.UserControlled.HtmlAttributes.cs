// WATCHER
//
// Check.Pasv.UserControlled.HtmlAttributes.cs
// Checks for places where user-controlled URL or Form POST parameters control HTML attributes.
//
// Copyright (c) 2010 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Text.RegularExpressions;
using Fiddler;
using Majestic12;

namespace CasabaSecurity.Web.Watcher.Checks
{
    public class CheckPasvUserControlledHTMLAttributes : WatcherCheck
    {
        [ThreadStatic] static private string alertbody = "";
        [ThreadStatic] static private int findingnum;

        // Remember to close the UtilityHtmlParser at the end of the Check()
        //[ThreadStatic] UtilityHtmlParser parser = new UtilityHtmlParser();

        public CheckPasvUserControlledHTMLAttributes()
        {
            CheckCategory = WatcherCheckCategory.UserControlled;
            LongName = "User Controlled - HTML element attributes (potential XSS).";
            LongDescription = "This check looks at user-supplied input in query string parameters and POST data to identify where certain HTML attribute values might be controlled. This provides hot-spot detection for XSS (cross-site scripting) that will require further review by a security analyst to determine exploitability. ";
            ShortName = "User controllable HTML element attribute (potential XSS)";
            ShortDescription = "User-controlled HTML attribute values were found.  Try injecting special characters such as ', \", <, and > to see if XSS might be possible.  The page at the following URL:\r\n\r\n";
            Reference = "http://websecuritytool.codeplex.com/wikipage?title=Checks#user-controlled-html-attribute";
            Recommendation = "Validate all input and sanitize output it before writing to any HTML attributes.";
        }

        private void AddAlert(Session session)
        {
            string name = ShortName;
            string text =

                ShortDescription +
                session.fullUrl + 
                "\r\n\r\nappears to include user input in: \r\n\r\n" +
                alertbody;

            WatcherEngine.Results.Add(WatcherResultSeverity.High, session.id, session.fullUrl, name, text, StandardsCompliance, findingnum, Reference);
        }

        private void AssembleAlert(String tag, String attribute, String parm, String val, String context)
        {
            findingnum++;
            alertbody = alertbody + findingnum.ToString() + ") a(n) '" 
                + tag + 
                "' tag '" + 
                attribute + 
                "' attribute\r\n\r\n" +
                "The user input found was:\r\n" +
                parm +
                "=" +
                val +
                "\r\n\r\n" +
                "The user-controlled value was:\r\n" +
                context +
                "\r\n\r\n\r\n";
        }

        /// <summary>
        /// Mainly looks to see if user-input controls certain attributes.  If the input is a URL, this attempts
        /// to see if the scheme or domain can be controlled.  If it's not, it attempts to see if the attribute
        /// data starts with the user-data.
        /// </summary>
        /// <param name="parms"></param>
        /// <param name="body"></param>
        /// <param name="tag"></param>
        /// <param name="attribute"></param>
        /// <param name="requiredAttribute"></param>
        /// <param name="requiredAttributeValue"></param>
        private void CheckTags(NameValueCollection parms, HTMLchunk chunk)
        {
            string paramValue;

            // Loop through all attributes of the current HTML element
            foreach (DictionaryEntry dictEntry in chunk.oParams)
            {
                // Ignore all action events e.g. onmouseover, onclick, on*
                if (dictEntry.Key.ToString().ToLower().StartsWith("on")) return;

                // Loop through all values in the user-controlled parameters
                foreach (string param in parms)
                {
                    paramValue = parms.Get(param);
                    paramValue = Utility.ToSafeLower(paramValue);

                    // Only look at user-controlled parameter values that are bigger than 1 character.
                    // This is kinda lame but reduces false positives.
                    if (paramValue.Length > 1 && dictEntry.Value.ToString().StartsWith(paramValue, StringComparison.InvariantCultureIgnoreCase))
                        AssembleAlert(chunk.sTag, dictEntry.Key.ToString(), param, paramValue, dictEntry.Value.ToString());
                }
            }
        }

        public override void Check(Session session)
        {
            NameValueCollection parms = null;
            alertbody = "";
            findingnum = 0;

            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname))
            {
                if (session.responseCode == 200 && session.responseBodyBytes.Length > 0)
                {
                    UtilityHtmlParser parser = new UtilityHtmlParser();
                    parser.Open(session);
                    if (parser.Parser == null) return;
                    HTMLchunk chunk;

                    parms = Utility.GetRequestParameters(session);

                    // If there was no user-supplied parms we don't care to continue.
                    if (parms != null && parms.Keys.Count > 0)
                    {
                        while ((chunk = parser.Parser.ParseNext()) != null)
                        {
                            // Check every open tag we encounter
                            if (chunk.oType == HTMLchunkType.OpenTag)
                            {
                                // Check the attributes of this tag
                                CheckTags(parms, chunk);
                            }
                        }
                        parser.Close();
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