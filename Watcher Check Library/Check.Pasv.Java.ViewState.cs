// WATCHER
//
// Check.Pasv.Java.ViewState.Mac.cs
// Checks JavaServer MyFaces for insecure ViewState.
//
// Copyright (c) 2010 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.UI;
using System.Collections.Generic;
using Fiddler;

namespace CasabaSecurity.Web.Watcher.Checks
{
    /// <summary>
    /// Look for insecure ViewState used by Sun Java Mojarra (http://java.sun.com/javaee/javaserverfaces/) and
    /// Apache MyFaces (http://myfaces.apache.org/).  Both are implementations of the JavaServer Faces standard 
    /// and both handle and reference ViewState the same way.  
    /// By default the ViewState data they pass between client and server is insecure and subject to tampering
    /// and XSS attacks - see the advisory https://www.trustwave.com/spiderlabs/advisories/TWSL2010-001.txt.
    /// 
    /// David Byrne described it as this:
    /// Regarding detection on JSF (Apache MyFaces & Sun Mojarra), they are Java object streams, so the format 
    /// is fairly predictable. The simplest way is probably to just check the value for plain text strings. 
    /// If it's unencrypted, there should be some Java class names, etc in there. There are a few different 
    /// encodings that can be used though. All of the JSF view state's I've seen are base64 encoded, 
    /// although I don't think they have to be. After decoding the base64, some may be compressed 
    /// with the gzip algorithm (which is the default). 
    /// 
    /// </summary>
    public class CheckPasvJavaServerFacesViewState : WatcherCheck
    {
        //[ThreadStatic] static private string alertbody = "";
        //[ThreadStatic] static private int findingnum;
        private EnableCheckConfigPanel configpanel;
        static private List<String> hosts = new List<String>();

        public CheckPasvJavaServerFacesViewState()
        {
            configpanel = new EnableCheckConfigPanel(this, "JavaServer Faces ViewState", "Reduce noise - enable only one ViewState finding per site.");
            configpanel.Init();

            CheckCategory = WatcherCheckCategory.Java;
            LongName = "JavaServer Faces - identify when ViewState data is insecure.";
            LongDescription = "This check looks at JavaServer Faces values implemented in Apache MyFaces and Sun's Mojarra project, to detect when cryptographic protection has been disabled. If disabled, it's possible for attackers to tamper with the ViewState and create XSS attacks.";
            ShortName = "JavaServer Faces ViewState vulnerable to tampering";
            ShortDescription = "The response at the following URL contains a ViewState value that has no cryptographic protections:\r\n\r\n";
            Reference = "http://websecuritytool.codeplex.com/wikipage?title=Checks#java-myfaces-viewstate";
            Recommendation = "Secure VIEWSTATE with a MAC specific to your environment.";
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
            lock (hosts)
            {
                hosts = new List<String>();
            }
        }

        private void AddAlert(Session session)
        {
            String name = ShortName;
            String text =
                ShortDescription +
                session.fullUrl +
                "\r\n\r\n";

            WatcherEngine.Results.Add(WatcherResultSeverity.High, session.id, session.fullUrl, name, text, StandardsCompliance, 1, Reference);
        }

        /// <summary>
        /// First base64 decode viewstate, then decompress it if it's gzipped.  Then look for clear text strings. 
        /// It's common for java class names to be present, so look for 'java' and others.  If they are readable
        /// then the viewstate is not protected with encryption.
        /// </summary>
        /// <param name="val">The ViewState value.</param>
        /// <returns>True if ViewState is cryptographically secure, False if not.</returns>
        private bool IsViewStateSecure(string val)
        {
            if (String.IsNullOrEmpty(val))
            {
                return true;
            }

            byte[] viewStateDecoded = { };

            ///////////////////////////////
            // Step 1
            // Base64 decode the ViewState.
            // TODO:  Some ViewState can use other encoding forms, research and add support for these.

            // Conversion may fail so catch exceptions.
            try
            {
                viewStateDecoded = Convert.FromBase64String(val);
                // If the value is null or byte array length is zero then bail.
                if (viewStateDecoded == null || viewStateDecoded.Length == 0)
                {
                    return true;
                }
            }
            catch (FormatException e)
            {
                // Thrown if the conversion fails because of invalid Base64
                Trace.TraceError("Error: FormatException: {0}", e.Message);
                // Since the Base64 decode failed, attempt to see if thie ViewState
                // is unencoded which is theoretically possible.  Look for string values like
                // 'java' to determine that it's insecure.
                if (val.Contains("java"))
                {
                    // ViewState is insecure
                    return false;
                }
                return true;
            }
            catch (ArgumentNullException e)
            {
                // Thrown if null arguments were passed
                Trace.TraceError("Error: ArgumentNullException: {0}", e.Message);
                return true;
            }

            ///////////////////////////////
            // Step 2
            // Decompress ViewState from gzip format (the default), or handle it as uncompressed (which is possible).
            //
            // There's two possibilities at this point, either the decoded ViewState is uncompressed or it's compressed.
            // If it's uncompressed then we can treat it as a string right away.  Attempt to do that 
            // using a UTF8 encoding, otherwise continue and try to GZIP deflate it.
            // 
            // TODO: Could other compression forms be used?

            // First attempt to treat the decoded ViewState as an uncompressed string.
            string viewStateDecodedNotCompressed = Encoding.UTF8.GetString(viewStateDecoded);
            // TODO: Improve this to look for more than just 'java'.  It's possible we could even have a false positive here.
            if (viewStateDecodedNotCompressed.Contains("java"))
            {
                // ViewState is insecure
                return false;
            }

            // If the above didn't return, then continue on trying to GZIP deflate the byte array.
            using (MemoryStream memStreamIn = new MemoryStream())
            {
                // Save the Base64 decoded ViewState to the memory stream.  If it's gzipped we'll decompress next.
                memStreamIn.Write(viewStateDecoded, 0, viewStateDecoded.Length);
                memStreamIn.Seek(0, SeekOrigin.Begin);
                using (MemoryStream memStreamOut = new MemoryStream())
                using (GZipStream Decompress = new GZipStream(memStreamIn, CompressionMode.Decompress))
                {
                    // What size should we set since we don't know?
                    byte[] buffer = new byte[4096];
                    try
                    {
                        int numRead;
                        while ((numRead = Decompress.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            memStreamOut.Write(buffer, 0, numRead);
                        }
                    }
                    catch (InvalidDataException e)
                    {
                        // Thrown 
                        Trace.TraceError("Error: {0}", e.Message);
                        return true;
                    }


                    ///////////////////////////////
                    // Step 3
                    // Try to determine if ViewState is encrypted or contains clear text strings.
                    // Usually there will be Java class names in there as well as other stuff.

                    byte[] viewStateBytes = memStreamOut.ToArray();
                    string viewStateDecompressed = Encoding.UTF8.GetString(viewStateBytes);
                    // TODO: Improve this to look for more than just 'java'. 
                    if (viewStateDecompressed.Contains("java"))
                    {
                        // ViewState is insecure
                        return false;
                    }
                    Decompress.Close();
                }
            }

            return true;
        }

        public bool SiteNotChecked(String hostname)
        {
            // We need to reset our hosts List when a user clicks the
            // Clear() button.  This is done through Watcher.cs clear button
            // event handler.
            // 
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

        public override void Check(Session session, UtilityHtmlParser htmlparser)
        {
            String bod = null;
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
                            bod = Utility.GetResponseText(session);
                            if (bod != null)
                            {
                                // Look at all <input> tags
                                foreach (Match m in Utility.GetHtmlTags(bod, "input"))
                                {
                                    id = Utility.GetHtmlTagAttribute(m.ToString(), "id");
                                    // Find ones where id="javax.faces.ViewState"
                                    //
                                    // TODO: Other possible field names include:
                                    // jsf_state_64
                                    // jsf_sequence
                                    // jsf_tree
                                    // jsf_tree_64
                                    // jsf_viewid
                                    // jsf_state

                                    if (id != null && (id.ToLower() == "javax.faces.viewstate"))
                                    {
                                        // Get the ViewState value
                                        val = Utility.GetHtmlTagAttribute(m.ToString(), "value");
                                        // Server-side ViewState usually comes down as an ID value like
                                        //    _id16683
                                        // Ignoring these for now.  Underscore is not a valid Base64 character
                                        // so it's safe to ignore this.
                                        if (val != null && val.StartsWith("_"))
                                        {
                                            return;
                                        }
                                        // If the ViewState is not secured cryptographic protections then raise an alert.
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
}