// WATCHER
//
// Check.Pasv.Flash.AllowScriptAccess.cs
// Checks for HTML object and embed tags that invoke Flash and insecurely set the AllowScriptAccess parameter..
//
// Copyright (c) 2010 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Diagnostics;
using System.Text.RegularExpressions;
using Fiddler;
using Majestic12;

namespace CasabaSecurity.Web.Watcher.Checks
{
    /// <summary>
    /// Look for instantiations of Adobe Flash Player which don't restrict javascript access. 
    /// Right now we look for <object> (IE) and <embed> (other browsers) HTML tags only which might cover most cases
    /// but will miss others who call Flash through javascript.
    /// 
    /// TODO: Once we get a javascript interpreter integrated, we can catch the other cases. 
    /// TODO: Modify check so it reports only one alert per request.
    /// </summary>
    public class CheckPasvFlashAllowScriptAccess : WatcherCheck
    {
        [ThreadStatic] static private string alertbody = "";
        [ThreadStatic] static private string alertbody2 = "";
        [ThreadStatic] static private string alertbody3 = "";
        [ThreadStatic] static private int findingnum;

        public CheckPasvFlashAllowScriptAccess()
        {
            CheckCategory = WatcherCheckCategory.Flash;
            LongName = "Flash - Look for instantiations of Adobe Flash Player which don't restrict javascript access.";
            LongDescription = "The Flash object includes a parameter named AllowScriptAccess which can be set to allow a Flash SWF file to access the browser's javascript DOM, even if the page embedding the SWF is different from the page hosting it. This means the SWF could inject javascript, open windows, or perform other dangerous actions if the SWF was vulnerable to such manipulation. Typical values are 'sameDomain', 'always', and 'never'. This check flags patterns which don't set this value to 'never', which allows script access. You may not be concerned when this value is set to 'sameDomain' as that limits the scope of access somewhat, however this gets flagged as well.";
            ShortName = "Flash allowScriptAccess";
            ShortDescription = "The page at the following URL specified a potentially insecure allowScriptAccess value when loading a flash SWF file:\r\n\r\n";
            Reference = "http://websecuritytool.codeplex.com/wikipage?title=Checks#flash-javascript-access";
            Recommendation = "Set AllowScriptAccess to 'never'.";
        }


        public override String GetName()
        {
            return LongName;
        }

        public override String GetDescription()
        {
            return LongDescription;
        }

        private void AddAlert(Session session, WatcherResultSeverity severity, String context)
        {
            String name = ShortName;
            String text =
                ShortDescription +
                session.fullUrl +
                "\r\n\r\n" +
                context;

            WatcherEngine.Results.Add(severity, session.id, session.fullUrl, name, text, StandardsCompliance, findingnum, Reference);
        }

        private String AssembleAlert(String alert, String value, String context)
        {
            findingnum++;
            alert = alert + findingnum.ToString() + ") The allowScriptAccess value specified was:\r\n" +
                value +
                "\r\n\r\n" +
                "The context was:\r\n" +
                context +
                "\r\n\r\n";
            return alert;
        }

        private void CheckAllowScriptAccessValue(String allowScriptAccessValue, String context)
        {
            if (allowScriptAccessValue != null)
            {
                allowScriptAccessValue = Utility.ToSafeLower(allowScriptAccessValue);
                if (allowScriptAccessValue == "always")
                    alertbody = AssembleAlert(alertbody, "Always", context);

                if (allowScriptAccessValue == "samedomain")
                    alertbody2 = AssembleAlert(alertbody2, "sameDomain", context);
            }
            else
            {
                alertbody3 = AssembleAlert(alertbody3, "No value set", context);
            }
        }

        private void CheckObjectTag(HTMLchunk chunk, ref UtilityHtmlParser parser)
        {
            String[] bods = null;
            String attr = null;
            String html = null;
            String allowScriptAccessValue = null;
            bool flag = false;

            string b = chunk.oHTML;

            // Check the param elements of an object element
            if (chunk.oParams.ContainsKey("classid"))
            {
                attr = chunk.oParams["classid"].ToString();
                if ((attr == "clsid:d27cdb6e-ae6d-11cf-96b8-444553540000") || (attr == "x-shockwave-flash")) // flash clsid
                {
                    allowScriptAccessValue = GetAllowScriptAccessValue(ref parser, ref flag, allowScriptAccessValue, ref html);

                    if (flag)
                        CheckAllowScriptAccessValue(allowScriptAccessValue, b);
                }
            }

            // Otherwise check the attributes of the object element
            if (chunk.oParams.ContainsKey("type"))
            {
                string type = chunk.oParams["type"].ToString();
                if (Utility.ToSafeLower(type) == "application/x-shockwave-flash" && chunk.oParams.ContainsKey("allowscriptaccess"))
                {
                    allowScriptAccessValue = chunk.oParams["allowscriptaccess"].ToString();
                    CheckAllowScriptAccessValue(allowScriptAccessValue, chunk.oHTML);
                }
                // Start looking through the param elements.
                else if (Utility.ToSafeLower(type) == "application/x-shockwave-flash")
                {
                    allowScriptAccessValue = GetAllowScriptAccessValue(ref parser, ref flag, allowScriptAccessValue, ref html);
                    CheckAllowScriptAccessValue(allowScriptAccessValue, html);
                }
            }
        }

        private string GetAllowScriptAccessValue(ref UtilityHtmlParser parser, ref bool flag, string allowScriptAccessValue, ref string html)
        {
            String name = null;
            String val = null;
            HTMLchunk chunk;
            while ((chunk = parser.Parser.ParseNext()) != null)
            {
                if (chunk.sTag == "param" && chunk.oParams.ContainsKey("name") && chunk.oParams.ContainsKey("value"))
                {
                    name = chunk.oParams["name"].ToString();
                    if (Utility.ToSafeLower(name) == "movie")
                    {
                        val = chunk.oParams["value"].ToString();
                        val = Utility.ToSafeLower(val);
                        if (val.Trim().EndsWith(".swf"))
                            flag = true;
                    }
                    if (Utility.ToSafeLower(name) == "allowscriptaccess")
                    {
                        allowScriptAccessValue = chunk.oParams["value"].ToString();
                        // Return the HTML where we want to report an issue.
                        html = chunk.oHTML;
                    }
                }
            }
            return allowScriptAccessValue;
        }

        private void CheckEmbedxTag(HTMLchunk chunk)
        {
            String value = null;

            if (chunk.oParams.ContainsKey("allowscriptaccess"))
            {
                try
                {
                    value = chunk.oParams["allowscriptaccess"].ToString();

                    if (!String.IsNullOrEmpty(value))
                        value = Utility.ToSafeLower(value);
                    CheckAllowScriptAccessValue(value, chunk.oHTML.ToString());
                }
                catch (Exception e)
                {
                    Trace.TraceWarning("Warning: Watcher check threw an unhandled exception: {0}", e.Message);
                    ExceptionLogger.HandleException(e);
                }
            }
        }

        public override void Check(Session session)
        {
            String bod = null;
            alertbody = "";
            alertbody2 = "";
            alertbody3 = "";
            findingnum = 0;

            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname))
            {
                if (session.responseCode == 200)
                {
                    if (Utility.IsResponseHtml(session))
                    {
                        UtilityHtmlParser parser = new UtilityHtmlParser();
                        parser.Open(session);
                        parser.Parser.bKeepRawHTML = true;
                        if (parser.Parser == null) return;

                        HTMLchunk chunk;
                        while ((chunk = parser.Parser.ParseNext()) !=null)
                        {
                            if (chunk.oType == HTMLchunkType.OpenTag)
                            {
                                if (chunk.sTag == "object")
                                {
                                    CheckObjectTag(chunk, ref parser);
                                }
                                if (chunk.sTag == "embed")
                                {
                                    CheckEmbedxTag(chunk);
                                }
                            }
                        }

                        if (!String.IsNullOrEmpty(alertbody))
                        {
                            AddAlert(session, WatcherResultSeverity.Medium, alertbody);
                        }
                        if (!String.IsNullOrEmpty(alertbody2))
                        {
                            AddAlert(session, WatcherResultSeverity.Informational, alertbody2);
                        }
                        if (!String.IsNullOrEmpty(alertbody3))
                        {
                            AddAlert(session, WatcherResultSeverity.Medium, alertbody3);
                        }
                    }
                }
            }
        }
    }
}