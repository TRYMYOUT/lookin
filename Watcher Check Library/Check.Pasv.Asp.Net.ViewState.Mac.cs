// WATCHER
//
// Check.Pasv.Asp.Net.ViewState.Mac.cs
// Checks ASP.NET VIEWSTATE for MAC validation protection.
//
// Copyright (c) 2010 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.UI;
using System.Collections.Generic;
using Fiddler;
using Majestic12;

namespace CasabaSecurity.Web.Watcher.Checks
{
    /// <summary>
    /// Look for ASP.NET VIEWSTATE that has the MAC protection disabled.  When disabled, the VIEWSTATE is vulnerable to tampering
    /// and XSS attacks - see the advisory https://www.trustwave.com/spiderlabs/advisories/TWSL2010-001.txt.
    /// 
    /// TODO: test if this works in all framework scenarios:
    /// .NET 4.0 - pass
    /// .NET 3.5 - pass
    /// .NET 3.0 - pass
    /// .NET 2.0 - pass
    /// .NET 1.1 - pass
    /// .NET 1.0 - todo (did 1.0 have a MAC protection?)
    /// 
    /// </summary>
    public class CheckPasvAspNetViewStateMac : WatcherCheck
    {
        //[ThreadStatic] static private string alertbody = "";
        //[ThreadStatic] static private int findingnum;
        private EnableCheckConfigPanel configpanel;
        static private List<String> hosts = new List<String>();

        public CheckPasvAspNetViewStateMac()
        {
            configpanel = new EnableCheckConfigPanel(this, "ASP.NET Viewstate", "Reduce noise - enable only one VIEWSTATE finding per site.");
            configpanel.Init();

            CheckCategory = WatcherCheckCategory.AspNet;
            LongName = "ASP.NET VIEWSTATE - identify when EnableViewStateMac setting has been disabled.";
            LongDescription = "This check looks at ASP.NET VIEWSTATE values to detect when MAC protection has been disabled. If disabled, it's possible for attackers to tamper with the VIEWSTATE and create XSS attacks.  More information is available from the advisory at https://www.trustwave.com/spiderlabs/advisories/TWSL2010-001.txt. \r\n\r\n  Use the configuration option below to reduce output from this check.  When enabled, only one VIEWSTATE finding will be reported per site.  As soon as a single VIEWSTATE finding is identified, no further checking would be done for that domain/site.  When disabled however, the VIEWSTATE will be checked on every single page and page request, which could generate a lot of findings when VIEWSTATE is insecure site-wide.  Keeping this option disabled will produce more thorough results across a site.";
            ShortName = "ASP.NET VIEWSTATE vulnerable to tampering";
            ShortDescription = "The response at the following URL contains a VIEWSTATE value that has MAC protections disabled:\r\n\r\n";
            Reference = "http://websecuritytool.codeplex.com/wikipage?title=Checks#asp-net-viewstate-tampering";
            Recommendation = "Secure VIEWSTATE with a MAC by setting EnableViewStateMac to true, which is on by default.";
        }


        public override System.Windows.Forms.Panel GetConfigPanel()
        {
            System.Windows.Forms.Panel panel = new System.Windows.Forms.Panel();
            panel.Dock = System.Windows.Forms.DockStyle.Fill;
            configpanel.Dock = System.Windows.Forms.DockStyle.Fill;
            panel.Controls.Add(configpanel);
            return panel;
        }

        public override void Clear()
        {
            // We need to reset our hosts List when a user clicks the
            // Clear() button.  This is done through Watcher.cs clear button
            // event handler.
            // 
            lock (hosts)
            {
                hosts = new List<String>();
            }
        }
        /// <summary>
        /// TODO: Extract the VIEWSTATE data in XML form and write it out in the alert (requires our pending VIEWSTATE decoder).
        /// </summary>
        /// <param name="session"></param>
        private void AddAlert(Session session)
        {
            String name = ShortName;
            String text =
                ShortDescription +
                session.fullUrl +
                "\r\n\r\n";

            WatcherEngine.Results.Add(WatcherResultSeverity.High, session.id, session.fullUrl, name, text, StandardsCompliance,0, Reference);
        }

        /// <summary>
        /// First base64 decode the VIEWSTATE value, then deserialize it with LosFormatter.  
        /// Check to see if the last 20 or 32 bytes make up a cryptographic MAC protection.
        /// In .NET 4.0, 32 bytes are used for the MAC.  In all other versions, 20 bytes.
        /// </summary>
        /// <param name="val">The VIEWSTATE value as a base64 encoded string</param>
        /// <returns></returns>
        private bool IsViewStateSecure(string val)
        {
            if (String.IsNullOrEmpty(val))
            {
                return true;
            }

            byte[] viewStateDeserialized = { };
            byte[] viewStateReSerialized = { };

            // Patrick Toomey seemed to have a good method for detecting whether MAC
            // validation was enabled or not.  See source code from:
            // http://labs.neohapsis.com/2009/08/03/viewstateviewer-a-gui-tool-for-deserializingreserializing-viewstate/
            //

            // Conversion may fail so catch exceptions.
            try
            {
                viewStateDeserialized = System.Convert.FromBase64String(val);
                // If the value is null or byte array length is zero then bail.
                if (viewStateDeserialized == null || viewStateDeserialized.Length == 0)
                {
                    return true;
                }
            }
            catch (FormatException e)
            {
                // Thrown if the conversion fails because of invalid Base64
                Trace.TraceError("Error: FormatException: {0}", e.Message);
                return true;
            }
            catch (ArgumentNullException e)
            {
                // Thrown if null arguments were passed
                Trace.TraceError("Error: ArgumentNullException: {0}", e.Message);
                return true;
            }

            // LosFormatter knows how to serialize and deserialize VIEWSTATE objects.
            // The default ctor will not use a MAC key.
            LosFormatter formatter = new LosFormatter();
            StringBuilder sb = new StringBuilder();
            StringWriter sw = new StringWriter(sb);

            // TODO: Need a try/catch here?
            formatter.Serialize(sw, formatter.Deserialize(val));

            try
            {
                viewStateReSerialized = System.Convert.FromBase64String(sb.ToString());

                // If the value is null or byte array length is zero then bail.
                if (viewStateReSerialized == null || viewStateReSerialized.Length == 0)
                {
                    return true;
                }
            }
            catch (FormatException e)
            {
                // Thrown if the conversion fails because of invalid Base64
                Trace.TraceError("Error: FormatException: {0}", e.Message);
                return true;
            }
            catch (ArgumentNullException e)
            {
                // Thrown if null arguments were passed
                Trace.TraceError("Error: ArgumentNullException: {0}", e.Message);
                return true;
            }

            // When serializing, LosFormatter will drop the MAC (last 20 bytes) if they exist.
            // So we can tell if a MAC was present by comparing  lenght of the deserialized and
            // reserialized VIEWSTATE for a difference of 20 bytes (.NET 1.1 - 3.5), or 32 bytes (.NET 4.0).

            if (viewStateDeserialized.Length != viewStateReSerialized.Length)
            {
                if (viewStateDeserialized.Length - viewStateReSerialized.Length == 20)
                {
                    // VIEWSTATE has MAC protection enabled
                    return true;
                }
                else if (viewStateDeserialized.Length - viewStateReSerialized.Length == 32)
                {
                    // VIEWSTATE has MAC protection enabled
                    return true;
                }
            }

            // Confirmed VIEWSTATE MAC protection is disabled.  This is equivalent to:
            // if (viewStateDeserialized.Length == viewStateReSerialized.Length)
            return false;
        }

        public bool SiteNotChecked(String hostname)
        {
            lock (hosts)
            {
                // host has already been checked
                if (hosts.Contains(hostname))
                {
                    return false;
                }

                // host has not been checked yet
                else
                {
                    // Only add the hostname if a finding was recorded
                    return true;
                }
            }
        }

        public override void Check(Session session, UtilityHtmlParser htmlParser)
        {
            Stopwatch sw = new Stopwatch();
            sw.Start();
            String id  = null;
            String val = null;

            bool filter = configpanel.enablefiltercheckBox.Checked;

            //alertbody = "";
            //findingnum = 0;

            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname))
            {
                if (session.responseCode == 200)
                {
                    if (Utility.IsResponseHtml(session))
                    {
                        if(!filter || SiteNotChecked(session.hostname)) 
                        {
                            HTMLchunk chunk;
                            while ((chunk = htmlParser.Parser.ParseNextTag()) != null)
                            {
                                if (chunk.oType == HTMLchunkType.OpenTag && chunk.sTag == "input")
                                {
                                    if (chunk.oParams.ContainsKey("id"))
                                    {
                                        id = chunk.oParams["id"].ToString();

                                        // Find ones where id="__VIEWSTATE"
                                        if (id.Equals("__VIEWSTATE", StringComparison.InvariantCultureIgnoreCase))
                                        {
                                            // Get the __VIEWSTATE value
                                            if (chunk.oParams.ContainsKey("value"))
                                            {
                                                val = chunk.oParams["value"].ToString();
                                                // If the VIEWSTATE is not secured with a MAC, then raise an alert.
                                                if (!IsViewStateSecure(val))
                                                {
                                                    lock (hosts)
                                                    {
                                                        hosts.Add(session.hostname);
                                                    }
                                                    AddAlert(session);
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
            sw.Stop();
            long time = sw.ElapsedMilliseconds;
        }
    }
}