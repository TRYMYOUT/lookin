// WATCHER
//
// Check.Pasv.Flash.AllowScriptAccess.cs
// Checks for HTML object and embed tags that invoke Flash and insecurely set the AllowScriptAccess parameter..
//
// Copyright (c) 2010 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Text.RegularExpressions;
using Fiddler;
using HtmlAgilityPack;

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
            if (!String.IsNullOrEmpty(allowScriptAccessValue))
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

        private void CheckObjectTag(UtilityHtmlDocument html)
        {
            String attr = null;
            String attr2 = null;
            String name = null;
            String allowScriptAccessValue = null;
            String val = null;
            bool flag = false;

            foreach (HtmlNode node in html.Nodes)
            {
                if (node.Name.ToLower() == "object")
                {
                    attr = node.GetAttributeValue("classid", "");
                    attr2 = node.GetAttributeValue("type", "");
                    if (!String.IsNullOrEmpty(attr) || !String.IsNullOrEmpty(attr2))
                    {
                        if ((attr == "clsid:d27cdb6e-ae6d-11cf-96b8-444553540000") || (attr2.Contains("x-shockwave-flash"))) // flash clsid
                        {
                            foreach (HtmlNode childnode in node.ChildNodes)
                            {
                                if (childnode.Name.ToLower() == "param")
                                {
                                    name = childnode.GetAttributeValue("name", "");
                                    if (!String.IsNullOrEmpty(name))
                                    {
                                        if (String.Equals("movie",name,StringComparison.InvariantCultureIgnoreCase))
                                        {
                                            val = childnode.GetAttributeValue("value", "");
                                            if (!String.IsNullOrEmpty(val))
                                                val = Utility.ToSafeLower(val);
                                            if (val.Trim().EndsWith(".swf"))
                                                flag = true;
                                        }

                                        if (String.Equals("allowscriptaccess",name, StringComparison.InvariantCultureIgnoreCase))
                                            allowScriptAccessValue = childnode.GetAttributeValue("value", "");
                                    }
                                }
                            }

                            if (flag)
                                CheckAllowScriptAccessValue(allowScriptAccessValue, node.OuterHtml);
                        }
                    }
                    String type = null;
                    // If the object node calls  Flash type application
                    type = node.GetAttributeValue("type", "");
                    if (!String.IsNullOrEmpty(type))
                        type = Utility.ToSafeLower(type);
                    if (type == "application/x-shockwave-flash")

                        foreach (HtmlNode child in node.ChildNodes)
                        {
                            if (child.Name.ToLower() == "param" && child.GetAttributeValue("name", "").ToLower() == "allowscriptaccess")
                            {
                                allowScriptAccessValue = child.GetAttributeValue("value","");
                                CheckAllowScriptAccessValue(allowScriptAccessValue, node.OuterHtml);
                            }
                        }
                }
            }
        }

        private void CheckEmbedxTag(UtilityHtmlDocument html)
        {
            String value = null;

            foreach (HtmlNode node in html.Nodes)
            {
                if (node.Name.ToLower() == "embed")
                {
                    value = node.GetAttributeValue("allowscriptaccess", "");
                    if (value != null)
                    {
                        CheckAllowScriptAccessValue(value, node.OuterHtml);
                    }
                }
            }
        }

        public override void Check(Session session, UtilityHtmlDocument html)
        {
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
                        if (html.Nodes.Count > 0)
                        {

                            CheckObjectTag(html);
                            CheckEmbedxTag(html);
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