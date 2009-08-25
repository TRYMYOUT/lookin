// WATCHER
//
// Check.Pasv.Javascript.Eval.cs
// Checks for use of javascript eval type functions.
//
// Copyright (c) 2009 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Text.RegularExpressions;
using Fiddler;

namespace CasabaSecurity.Web.Watcher.Checks
{
    //TODO: Provide line numbers for Javascript evals
    public class CheckPasvJavascriptEval : WatcherCheck
    {
        private int findingnum;
        private string alertbody;

        public override String GetName()
        {
            return "Javascript - Examine javascript code for use of dangerous eval() methods.";
        }

        public override String GetDescription()
        {
            String desc = "This check identifies the use of eval(), setTimeout(), and setInterval() in javascript code.  " +
                "These functions evaluate a string and execute it as javascript code.  When they're passed attacker-controlled " +
                "values, cross-site scripting and other attacks could be possible.  These findings should be reviewed by a " +
                "security analyst for exploitability.  Their use may also violate your organizational policy.";

            return desc;
        }

        private void AddAlert(Session session)
        {
            String name = "Javascript eval() usage";
            String text =

                name +
                "\r\n\r\n" +
                "Risk: Medium\r\n\r\n" +
                "The page at the following URL appears to contain javascript that calls the eval() function:\r\n\r\n" +
                session.url +
                "\r\n\r\n" +
                "The context was:\r\n\r\n" +
                alertbody;

            WatcherEngine.Results.Add(WatcherResultSeverity.Medium, session.id, session.url, name, text, StandardsCompliance, findingnum);
        }

        private void CheckJavascriptEvalUsage(Session session, String body)
        {
            String[] funcs = { "eval", "setTimeout", "setInterval", "execScript" };

            foreach (String func in funcs)
                //foreach (Match m in Regex.Matches(body, @"^(?>(eval)\((?<LEVEL>)|\)(?<-LEVEL>)|(?! \( | \) ).)+(?(LEVEL)(?!))$", RegexOptions.Singleline)) 
                foreach (Match m in Regex.Matches(body, "(^|\\s+?)" + func + "\\s*?\\(.*?\\)", RegexOptions.Singleline))
                {
                    findingnum++;
                    alertbody = alertbody + findingnum.ToString() + ") " + m.ToString().Trim() + "\r\n\r\n";
                }
        }

        public override void Check(Session session, UtilityHtmlParser htmlparser)
        {
            String[] bods = null;
            String body = null;
            alertbody = "";
            findingnum = 0;

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
                                        CheckJavascriptEvalUsage(session, b);
                            }

                            if (Utility.IsResponseJavascript(session))
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
}