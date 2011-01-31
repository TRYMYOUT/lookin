// WATCHER
//
// Check.Pasv.Silverlight.EnableHtmlAccess.cs
// Checks for HTML object and embed tags that invoke Silverlight and insecurely set the EnableHtmlAccess parameter..
//
// Copyright (c) 2010 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.Collections.Specialized;
using Fiddler;

namespace CasabaSecurity.Web.Watcher.Checks
{
    /// <summary>
    /// Look for instantiations of Silverlight Player which don't restrict javascript access. 
    /// Right now we look for <object> (IE) and <embed> (other browsers) HTML tags only which might cover most cases
    /// but will miss others who call Flash through javascript.
    /// 
    /// References: 
    /// http://msdn.microsoft.com/en-us/library/cc838264(VS.95).aspx
    /// http://msdn.microsoft.com/en-us/library/cc189089(VS.95).aspx
    /// http://www.informit.com/articles/article.aspx?p=1078181
    /// 
    /// TODO: Once we get a javascript interpreter integrated, we can catch the other cases. 
    /// TODO: Modify check so it reports only one alert per request.
    /// 
    /// Test Cases:
    /// **** Are EMBED tags used with Silverlight????
    /// 1) Alert when enablehtmlaccess attribute value is true inside an embed tag 
    /// <embed type="x-silverlight" enablehtmlaccess="true"></embed>
    /// 2) Alert when enablehtmlaccess parameter value is true inside an <object> tag where any of the object attributes:
    ///   a) classid = clsid:89F4137D-6C26-4A84-BDB8-2E5A4BB71E00
    ///   b) classid = x-silverlight
    ///   c) type = x-silverlight
    ///   d) data = x-silverlight
    ///   
    ///   and the type parameter value ends with .xap
    ///   
    ///   <object id="SilverlightPlugin1" width="300" height="300"
    ///	    data="data:application/x-silverlight-2," 
    ///	    type="application/x-silverlight-2" >
    ///     <param name="type" value="file.xap"></param>
    ///     <param name="enablehtmlaccess" value="true"></param>
    ///   </object>

    /// 
    /// </summary>
    public class CheckPasvSilverlightAllowHtmlAccess : WatcherCheck
    {
        [ThreadStatic] static private string alertbody = "";
        [ThreadStatic] static private string alertbody2 = "";
        [ThreadStatic] static private int findingnum;

        public CheckPasvSilverlightAllowHtmlAccess()
        {
            CheckCategory = WatcherCheckCategory.Silverlight;
            LongName = "Silverlight - Look for instantiations of Silverlight Player which don't restrict javascript access.";
            LongDescription = "The Silverlight object includes a parameter named EnableHtmlAccess which can be used to scope how javascript can access the Silverlight code. Values can be either true or false.  This check flags patterns which don't set this value to 'false', which allows script access.";
            ShortName = "Silverlight EnableHtmlAccess";
            ShortDescription = "The page at the following URL specified a potentially insecure EnableHtmlAccess value when loading a Silverlight XAP file.  When enabled, this value allows javascript access to the Silverlight code:\r\n\r\n";
            Reference = "http://websecuritytool.codeplex.com/wikipage?title=Checks#silverlight-javascript-access";
            Recommendation = "Set the EnableHtmlAccess parameter to 'false'.";
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
            alert = alert + findingnum.ToString() + ") The EnableHtmlAccess value specified was:\r\n" +
                value +
                "\r\n\r\n" +
                "The context was:\r\n" +
                context +
                "\r\n\r\n";
            return alert;
        }

        private void CheckEnableHtmlAccessValue(String value, String context)
        {
            if (value != null || value != "")
            {
                if (value == "true")
                    alertbody = AssembleAlert(alertbody, "true", context);

            }
            else
            {
                alertbody2 = AssembleAlert(alertbody2, "No value set", context);
            }
        }

       
        /// <summary>
        /// Check the OBJECT tag for an enableHtmlAccess parameter set to 'true'.
        /// See http://msdn.microsoft.com/en-us/library/cc189089(VS.95).aspx
        /// </summary>
        /// <param name="bod">The OBJECT tag content</param>
        private void CheckObjectTag(String bod)
        {
            String[] bods = null;
            String attr = null;
            String attr2 = null;
            String attr3 = null;
            String name = null;
            String enableHtmlAccessValue = null;
            String val = null;
            bool flag = false;

            bods = Utility.GetHtmlTagBodies(bod, "object", false);
            if (bods != null)
            {
                foreach (String b in bods)
                {
                    attr = Utility.ToSafeLower(Utility.GetHtmlTagAttribute(b, "classid"));
                    attr2 = Utility.ToSafeLower(Utility.GetHtmlTagAttribute(b, "type"));
                    attr3 = Utility.ToSafeLower(Utility.GetHtmlTagAttribute(b, "data"));

                    if ((attr != null && attr == "clsid:89F4137D-6C26-4A84-BDB8-2E5A4BB71E00".ToLower()) || 
                        (attr != null && (attr.Contains("x-silverlight"))) ||
                        (attr2 != null && (attr2.Contains("x-silverlight"))) ||
                        (attr3 != null && (attr2.Contains("x-silverlight")))
                        )
                    {
                        foreach (Match param in Utility.GetHtmlTags(b, "param"))
                        {
                            name = Utility.ToSafeLower(Utility.GetHtmlTagAttribute(param.ToString(), "name"));
                            if (name != null)
                            {
                                // The PARAM should contain an attribute named SOURCE pointing to
                                // the .XAP or .XAML file to load.
                                if (name == "source")
                                {
                                    val = Utility.ToSafeLower(Utility.GetHtmlTagAttribute(param.ToString(), "value"));
                                    if (val != null)
                                        if ((val.Trim().EndsWith(".xap")) || (val.Trim().EndsWith(".xaml")))
                                            flag = true;
                                }

                                if (name == "enablehtmlaccess")
                                {
                                    enableHtmlAccessValue = Utility.ToSafeLower((Utility.GetHtmlTagAttribute(param.ToString(), "value")));
                                }
                            }
                        }

                        if (flag)
                        {
                            CheckEnableHtmlAccessValue(enableHtmlAccessValue, b);
                        }
                    }
                    String type = null;
                    type = Utility.GetHtmlTagAttribute(b, "type");
                    if (type != null)
                        if (type.ToLower().Contains("x-silverlight"))
                            CheckEnableHtmlAccessValue(Utility.GetHtmlTagAttribute(b, "enablehtmlaccess"), b);
                }
            }
        }

        /// <summary>
        /// Check the EMBED tag for its enableHtmlAccess value.
        /// Silverlight can be embedded using the EMBED element tag.
        /// See http://www.informit.com/articles/article.aspx?p=1078181
        /// </summary>
        /// <param name="bod"></param>
        private void CheckEmbedTag(String bod)
        {
            String value = null;

            foreach (Match m in Utility.GetHtmlTags(bod, "embed"))
            {
                value = Utility.ToSafeLower(Utility.GetHtmlTagAttribute(m.ToString(), "enablehtmlaccess"));
                if (value != null)
                    CheckEnableHtmlAccessValue(value, m.ToString());
            }
        }

        public override void Check(Session session)
        {
            String bod = null;
            alertbody = "";
            alertbody2 = "";
            findingnum = 0;

            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname))
            {
                if (session.responseCode == 200)
                {
                    if (Utility.IsResponseHtml(session))
                    {
                        bod = Utility.GetResponseText(session);
                        if (bod != null)
                        {
                            bod = Utility.ToSafeLower(bod); ;

                            CheckObjectTag(bod);
                            CheckEmbedTag(bod);
                        }
                        if (!String.IsNullOrEmpty(alertbody))
                        {
                            AddAlert(session, WatcherResultSeverity.Medium, alertbody);
                        }
                        if (!String.IsNullOrEmpty(alertbody2))
                        {
                            AddAlert(session, WatcherResultSeverity.Low, alertbody2);
                        }
                    }
                }
            }
        }
    }
}