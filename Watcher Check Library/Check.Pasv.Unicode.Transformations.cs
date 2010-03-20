// WATCHER
//
// Check.Pasv.Unicode.Transformations.cs
// Checks for Unicode transformation hotspots.
//
// Copyright (c) 2009 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Globalization;
using System.Text;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Text.RegularExpressions;
using Fiddler;

namespace CasabaSecurity.Web.Watcher.Checks
{
    public class CheckPasvUnicodeTransformations : WatcherCheck
    {
        private string alertbody = "";
        private int findingnum;

        public override String GetName()
        {
            return "(EXPERIMENTAL) Unicode - find string transformation hot-spots for Normalization, ToUpper, ToLower, and Best-fit mappings.";
        }

        public override String GetDescription()
        {
            String desc = "This check reviews the byte stream of an UTF-8 encoded HTML page, and identifies " +
                    "where user-supplied input may have been transformed through casing or normalization " +
                    "operations.  The length of input parameters must be greater than one character for them " +
                    "to be considered.  For example, the following " +
                    "would be considered because the 'input' parameter value is four characters long: " +
                    "http://nottrusted.com/page?input=ＡＢＣＤ" + "\r\n" +
                    "For more information, check out: \r\n" +
                    "http://www.lookout.net/";

            return desc;
        }

        private void AddAlert(Session session)
        {
            string name = "Unicode string transformation were detected.";
            string text =

                name +
                "\r\n\r\n" +
                "Risk: Informational\r\n\r\n" +
                "Transformations on user-supplied strings include Normalization, " +
                "ToUpper, ToLower, and Best-fit mappings.  These could be vulnerable " +
                "to clever manipulation to control the HTML or javascript.  Certain " +
                "characters may be useful for further testing.  See http://www.lookout.net " +
                "for some examples and test cases.\r\n\r\n" +
                "The page at the following URL: \r\n\r\n" +
                session.url +
                " appears to include user input in: \r\n\r\n" +
                alertbody;

            WatcherEngine.Results.Add(WatcherResultSeverity.Informational, session.id, session.url, name, text, StandardsCompliance, findingnum);
        }

        private void AssembleAlert(String tag, String attribute, String parm, String val, String context)
        {
            String source = String.Empty;
            findingnum++;
            if (tag.Equals("text"))
            {
                source = "HTML text";
            }
            else
            {
                source = "A(n) '" + tag + "' element '" + attribute + "' attribute";
            }
            alertbody = alertbody + findingnum.ToString() + ") " +
                source + " was found with a user-supplied string transformed using " + context +
                "\r\n\r\n" +
                "The user input was:\r\n" +
                parm +
                "=" +
                val +
                "\r\n\r\n\r\n";
        }

        private void CheckHtmlElements(NameValueCollection parms, List<HtmlElement> htmlElements)
        {
            String val = null;

            foreach (HtmlElement element in htmlElements)
            {
                Dictionary<String, List<String>>.KeyCollection keyCollAtt = element.att.Keys;
                foreach (String attribute in keyCollAtt)
                {
                    foreach (String value in element.att[attribute])
                    {
                        foreach (String parm in parms.Keys)
                        {
                            val = parms.Get(parm);
                            if (val.Length > 1000) break;

                            // Don't need to parse strings since I want to know
                            // if the value is contained within any part of the string.
                            string[] split = value.Split(new Char[] { ';', '=', ',', '&', '/', ' ' });

                            // So in the following if statements, I'm trying follow a process:
                            // 1. Make sure the source val (user-input) isn't already normalized, lowered, uppered,
                            //      or best-fit.  If it was then we'd get false positives.
                            // 2. Test if the att (attribute value) contains a version of the source val that's
                            //      either normalized, lowered/uppered, or best-fit.
                            // This is all really low-budget and may be false-positive prone.
                            // Require more than 1 character to be concerned.
                            if (val != null && val.Length > 1)
                            {
                                foreach (String s in split)
                                {
                                    if (!(GetNormalizeC(val).Equals(val)) & value.Equals(GetNormalizeC(val)))
                                        AssembleAlert(element.tag, attribute, parm, val, "Normalization Form C:\r\n\r\n" + value.ToString());
                                    if (!(GetNormalizeD(val).Equals(val)) & value.Equals(GetNormalizeD(val)))
                                        AssembleAlert(element.tag, attribute, parm, val, "Normalization Form D:\r\n\r\n" + value.ToString());
                                    if (!(GetNormalizeKC(val).Equals(val)) & value.Equals(GetNormalizeKC(val)))
                                        AssembleAlert(element.tag, attribute, parm, val, "Normalization Form KC:\r\n\r\n" + value.ToString());
                                    if (!(GetNormalizeKD(val).Equals(val)) & value.Equals(GetNormalizeKD(val)))
                                        AssembleAlert(element.tag, attribute, parm, val, "Normalization Form KD:\r\n\r\n" + value.ToString());
                                    if (!(GetToLower(val).Equals(val)) & value.Equals(GetToLower(val)))
                                        AssembleAlert(element.tag, attribute, parm, val, "ToLower():\r\n\r\n" + value.ToString());
                                    if (!(GetToUpper(val).Equals(val)) & value.Equals(GetToUpper(val)))
                                        AssembleAlert(element.tag, attribute, parm, val, "ToUpper():\r\n\r\n" + value.ToString());
                                    if (!(GetBestFit(val).Equals(val)) & value.Equals(GetBestFit(val)))
                                        AssembleAlert(element.tag, attribute, parm, val, "Best-fit mappings:\r\n\r\n" + value.ToString());
                                }
                            }
                        }
                    }
                }
            }
        }

        private void CheckHtmlText(NameValueCollection parms, List<String> htmlText)
        {
            String val = String.Empty;

            foreach (String text in htmlText)
            {
                foreach (String parm in parms.Keys)
                {
                    val = parms.Get(parm);
                    if (val.Length > 1000) break;

                    // Don't need to parse strings since I want to know
                    // if the value is contained within any part of the string.
                    string[] split = text.Split(new Char[] { ';', '=', ',', '&', '/', ' ' });

                    // So in the following if statements, I'm trying follow a process:
                    // 1. Make sure the source val (user-input) isn't already normalized, lowered, uppered,
                    //      or best-fit.  If it was then we'd get false positives.
                    // 2. Test if the att (attribute value) contains a version of the source val that's
                    //      either normalized, lowered/uppered, or best-fit.
                    // This is all really low-budget and may be false-positive prone.
                    // Require more than 1 character to be concerned.
                    if (val != null && val.Length > 1)
                    {
                        foreach (String s in split)
                        {
                        if (!(GetNormalizeC(val).Equals(val)) & text.Equals(GetNormalizeC(val)))
                            AssembleAlert("text", null, parm, val, "Normalization Form C:\r\n\r\n" + text.ToString());
                        if (!(GetNormalizeD(val).Equals(val)) & text.Equals(GetNormalizeD(val)))
                            AssembleAlert("text", null, parm, val, "Normalization Form D:\r\n\r\n" + text.ToString());
                        if (!(GetNormalizeKC(val).Equals(val)) & text.Equals(GetNormalizeKC(val)))
                            AssembleAlert("text", null, parm, val, "Normalization Form KC:\r\n\r\n" + text.ToString());
                        if (!(GetNormalizeKD(val).Equals(val)) & text.Equals(GetNormalizeKD(val)))
                            AssembleAlert("text", null, parm, val, "Normalization Form KD:\r\n\r\n" + text.ToString());
                        if (!(GetToLower(val).Equals(val)) & text.Equals(GetToLower(val)))
                            AssembleAlert("text", null, parm, val, "ToLower():\r\n\r\n" + text.ToString());
                        if (!(GetToUpper(val).Equals(val)) & text.Equals(GetToUpper(val)))
                            AssembleAlert("text", null, parm, val, "ToUpper():\r\n\r\n" + text.ToString());
                        if (!(GetBestFit(val).Equals(val)) & text.Equals(GetBestFit(val)))
                            AssembleAlert("text", null, parm, val, "Best-fit mappings:\r\n\r\n" + text.ToString());
                        }
                    }
                }
            }
        }

        private static string GetNormalizeC(string strInput)
        {
            StringInfo.ParseCombiningCharacters(strInput);
            strInput = strInput.Normalize(NormalizationForm.FormC);
            return strInput;
        }

        private static string GetNormalizeD(string strInput)
        {
            StringInfo.ParseCombiningCharacters(strInput);
            strInput = strInput.Normalize(NormalizationForm.FormD);
            return strInput;
        }

        private static string GetNormalizeKC(string strInput)
        {
            StringInfo.ParseCombiningCharacters(strInput);
            strInput = strInput.Normalize(NormalizationForm.FormKC);
            return strInput;
        }

        private static string GetNormalizeKD(string strInput)
        {
            StringInfo.ParseCombiningCharacters(strInput);
            strInput = strInput.Normalize(NormalizationForm.FormKD);
            return strInput;
        }

        private static string GetToUpper(string strInput)
        {
            StringInfo.ParseCombiningCharacters(strInput);
            strInput = strInput.ToUpper();
            return strInput;
        }

        private static string GetToLower(string strInput)
        {
            StringInfo.ParseCombiningCharacters(strInput);
            strInput = strInput.ToLower();
            return strInput;
        }

        private static string GetBestFit(string strInput)
        {
            Encoding e = Encoding.GetEncoding("windows-1252");
            //UnicodeEncoding u;
            StringInfo.ParseCombiningCharacters(strInput);
            // the call to GetBytes causes a best-fit
            Byte[] bytes = e.GetBytes(strInput);
            char[] bytechars = new char[e.GetCharCount(bytes, 0, bytes.Length)];
            e.GetChars(bytes, 0, bytes.Length, bytechars, 0);
            //Byte[] bytesConverted = { };
            //bytesConverted = Encoding.Convert(UnicodeEncoding.Unicode, e, bytes);
            string strOutput = new string(bytechars);
            return strOutput;
        }

        public override void Check(Session session, UtilityHtmlParser htmlparser)
        {
            NameValueCollection parms = null;
            String body = null;
            alertbody = "";
            findingnum = 0;
            List<HtmlElement> htmlElements = htmlparser.HtmlElementCollection;
            List<String> htmlText = htmlparser.HtmlTextCollection;

            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname))
            {
                if (session.responseCode == 200)
                {
                    if (Utility.IsResponseHtml(session))
                    {
                        body = Utility.GetResponseText(session);
                        if (body != null)
                        {
                            parms = GetRequestParameters(session);

                            if (parms != null && parms.Keys.Count > 0)
                            {
                                //CheckResponseBody(parms, body
                                // Lazy match any attribute in any HTML element/tag
                                CheckHtmlElements(parms, htmlElements );
                                CheckHtmlText(parms, htmlText);
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