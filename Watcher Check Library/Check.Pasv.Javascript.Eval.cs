// WATCHER
//
// Check.Pasv.Javascript.Eval.cs
// Checks for use of javascript eval type functions.
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
    //TODO: Provide line numbers for Javascript evals
    public class CheckPasvJavascriptEval : WatcherCheck
    {
        [ThreadStatic] static private int findingnum;
        [ThreadStatic] static private string alertbody = "";

        public CheckPasvJavascriptEval()
        {
            // Complies with Microsoft SDL
            StandardsCompliance =
                WatcherCheckStandardsCompliance.MicrosoftSDL;

            CheckCategory = WatcherCheckCategory.JavaScript;
            LongName = "Javascript - Examine javascript code for use of dangerous eval() methods.";
            LongDescription = "This check identifies the use of eval(), setTimeout(), and setInterval() in javascript code. These functions evaluate a string and execute it as javascript code. When they're passed attacker-controlled values, cross-site scripting and other attacks could be possible. These findings should be reviewed by a security analyst for exploitability. Their use may also violate your organizational policy.";
            ShortName = "Javascript eval() usage";
            ShortDescription = "The page at the following URL appears to contain javascript that calls the eval() function:\r\n\r\n";
            Reference = "http://websecuritytool.codeplex.com/wikipage?title=Checks#javascript-eval";
            Recommendation = "Never pass un-sanitized user-input to eval() statements.";
        }

        private void AddAlert(Session session)
        {
            String name = ShortName;
            String text =

                ShortDescription +
                session.fullUrl +
                "\r\n\r\n" +
                "The context was:\r\n\r\n" +
                alertbody;

            WatcherEngine.Results.Add(WatcherResultSeverity.Medium, session.id, session.fullUrl, name, text, StandardsCompliance, 1, Reference);
        }

        private void CheckJavascriptEvalUsage(Session session, String input)
        {
            if (String.IsNullOrEmpty(input)) return;

            String[] funcs = { "eval", "setTimeout", "setInterval", "execScript" };
            //const string postPattern = @"((?'Open'\()+[^)]*(?'Close-Open'\))+)[^(]*(?(Open)(?!))";

            foreach (String func in funcs)
            {
                //string pattern = func + postPattern;
                //foreach (Match m in Regex.Matches(body, "(^|\\s+?)" + func + "\\s*?\\(.*?\\)", RegexOptions.Singleline))
                foreach (Match m in Regex.Matches(input, @"\s*?" + func + @"\s*?((?'Open'\()+[^)]*(?'Close-Open'\))+)[^(]*(?(Open)(?!))", RegexOptions.Singleline))
                {
                    findingnum++;
                    alertbody = alertbody + findingnum.ToString() + ") " + m.ToString().Trim() + "\r\n\r\n";
                }
            }
        }

        public override void Check(Session session, UtilityHtmlDocument html)
        {
            String body = null;
            alertbody = "";
            findingnum = 0;

            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname))
            {
                if (session.responseCode == 200)
                {
                    if (Utility.IsResponseHtml(session))
                    {
                        foreach (HtmlNode node in html.Nodes)
                        {
                            if (node.Name.ToLower() == "script")
                            {
                                CheckJavascriptEvalUsage(session, node.InnerText);
                            }
                        }
                    }
                    if (Utility.IsResponseJavascript(session))
                    {
                        body = Utility.GetResponseText(session);
                        CheckJavascriptEvalUsage(session, body);
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