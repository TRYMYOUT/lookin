using System;
using System.IO;
using System.Collections.Generic;
using System.Text;
using System.Xml;
using System.Web;
using System.Threading;
using System.Windows.Forms;
using CasabaSecurity.Web.Watcher.Collections;

namespace CasabaSecurity.Web.Watcher
{
    public class WatcherReportHTML : WatcherOutputPlugin
    {

        private XmlDocument doc;

        public WatcherReportHTML()
        {
        }

        public override String GetName()
        {
            return "HTML Report";
        }

        public override String GetDescription()
        {
            // TODO: String.Empty
            return "";
        }

        public override Panel GetConfigPanel()
        {
            return null;
        }

        public override bool GetExportDefaults(ref String defaultFilename, ref String defaultFilter)
        {
            defaultFilename = "watcher.html";
            defaultFilter = "HTML File (*.html)|*.html";
            return true;
        }

        public override Stream SaveResult(WatcherResultCollection resultslist)
        {
            MemoryStream s = new MemoryStream();
            XmlDocument doc = GetHtmlReport(resultslist);

            WatcherEngine.ProgressDialog.UpdateProgress("Saving HTML document...");
            
            if (doc != null)
            {
                doc.Save(s);
                return s;
            }

            return null;
        }

        private XmlDocument GetHtmlReport(WatcherResultCollection resultslist)
        {
            doc = new XmlDocument();
            XmlDocumentType doctype;

            // The HTML element
            XmlElement root = doc.DocumentElement;
            // The HEAD element
            XmlElement head = null;
            XmlElement title = null;
            // The meta tag element
            XmlElement meta = null;
            // The style element
            XmlElement style = null;
            XmlElement script = null;
            XmlElement toggleHidden = null;
            // The body element
            XmlElement body = null;
            XmlElement level = null;
            XmlElement url = null;
            XmlElement typex = null;
            XmlElement desc = doc.DocumentElement;
            XmlElement divResults = doc.DocumentElement;
            XmlElement divTOC = doc.DocumentElement;
            XmlDocumentFragment metaIE = null;

            string css = @" 
                            body {
                                font-family: 'Arial';
                                font-size: 12pt;
                            }
                            .issue {
                                margin-left: 30px;
                                display: block;
                            }
                            .type {
                                color: #FF0000;
                                font-size: 15pt;
                                display: block;
                            }
                            .level:before {
                                font-weight: bolder;
                                font-variant:small-caps;
                                content: 'severity: ';
                            }
                            .level {
                                display: block;
                            }
                            pre {
                                visibility: hidden;
                                display: none;
                            }
                            .description {
                                width: 80%;
                                margin-bottom: 30pt;
                                margin-left: 30pt;
                                white-space: pre; 
                            }
                            .toggler {
                                font-weight: normal;
                                font-style:italic;
                            }
                            .toggler:before {
                                font-style:normal;
                                font-weight: bolder;
                                font-variant:small-caps;
                                content: 'description: ';
                                text-decoration: none;
                            }
                            .url {
                                display: block;
                            }
                            .url:before {
                                font-weight: bolder;
                                font-variant:small-caps;
                                content: 'url: ';
                                text-decoration: none;
                            }
                            ";
            string js = @"
                            function toggleVisibility(id){
                                var elem = document.getElementById(id);
	                            if (elem.style.visibility=='hidden'){
		                            elem.style.visibility='visible';
                                    elem.style.display = 'block';
		                            }
	                            else {
		                            elem.style.visibility='hidden';
                                    elem.style.display = 'none';
		                            }
	                        }
                            ";

            string introduction = @"<h1>Watcher Security Report</h1>
                                <p>The following issues were automatically identified by the <a href='http://www.casabasecurity.com'>Watcher security plugin</a>
                                for <a href='http://www.fiddler2.com'>Fiddler</a>.</p>";

            doctype = doc.CreateDocumentType("html", "-//W3C//DTD XHTML 1.0 Transitional//EN", null, null);
            doc.AppendChild(doctype);
            root = doc.CreateElement("html");
            doc.AppendChild(root);

            head = doc.CreateElement("head");
            root.AppendChild(head);
            // Add a title
            title = doc.CreateElement("title");
            title.InnerText = "Watcher Security Report";
            head.AppendChild(title);

            // Setup the meta tag
            meta = doc.CreateElement("meta");
            meta.SetAttribute("http-equiv", "Content-Type");
            meta.SetAttribute("content", "text/html; charset=utf-8");
            head.AppendChild(meta);
            metaIE = doc.CreateDocumentFragment();
            metaIE.InnerXml = "<meta http-equiv='x-ua-compatible' content='IE=8' />";
            head.AppendChild(metaIE);
            // Setup the style tag
            style = doc.CreateElement("style");
            style.SetAttribute("type", "text/css");
            style.InnerXml = css;
            head.AppendChild(style);
            // Setup script tag
            script = doc.CreateElement("script");
            script.SetAttribute("language", "JavaScript");
            script.InnerXml = js; ;
            head.AppendChild(script);


            // Create the body tag
            body = doc.CreateElement("body");
            body.InnerXml = introduction;
            // Insert the body after the head
            root.InsertAfter(body, head);

            // Create a TOC and intro
            divTOC = doc.CreateElement("div");
            divTOC.SetAttribute("class", "TOC");
            divTOC.SetAttribute("id", "TOC");
            // Start the ordered list
            string contents = "<ol>";

            // Create div to hold selectedResults
            divResults = doc.CreateElement("div");
            divResults.SetAttribute("class", "selectedResults");
            divResults.SetAttribute("id", "selectedResults");

            int x = 0;
            foreach (WatcherResult item in resultslist)
            {
                WatcherEngine.ProgressDialog.labelOperation.Text = "Saving Watcher Finding: " + item.Title;
                WatcherEngine.ProgressDialog.ProgressValue = WatcherEngine.ProgressDialog.ProgressValue + (90 / resultslist.Count);

                level = doc.CreateElement("span");
                level.SetAttribute("class", "level");
                // Safe from XSS, we control this and its treated as text.
                level.InnerText = item.Severity.ToString();

                url = doc.CreateElement("span");
                url.SetAttribute("class", "url");
                // Use InnertText for URL to make it safe from XSS
                url.InnerText = item.URL;

                typex = doc.CreateElement("span");
                typex.SetAttribute("class", "type");
                // Safe from XSS, we control this and its treated as text.
                typex.InnerXml = "<a name='content-" + x + "'>" + item.Title + "</a>";

                // Update the string holding the TOC
                // Link to anchor
                contents = String.Concat(contents, String.Format("<li><a href='#content-{0}' class='list'>{1}</a></li>\r\n", x, item.Title));

                toggleHidden = doc.CreateElement("span");
                toggleHidden.SetAttribute("class", "toggler");
                toggleHidden.InnerXml = "<input type=\"button\" value=\"show/hide\" onclick=\"toggleVisibility('description-" + x + "');\" />";

                desc = doc.CreateElement("pre");
                desc.SetAttribute("class", "description");
                desc.SetAttribute("id", "description-" + x);
                desc.SetAttribute("style", "visibility:hidden;display:none");
                // Safe from XSS, we control this and its treated as text.
                desc.InnerText = item.Description;

                divResults.AppendChild(typex);
                divResults.AppendChild(level);
                divResults.AppendChild(url);
                divResults.AppendChild(toggleHidden);
                divResults.AppendChild(desc);
                x++;
            }
            // Append the TOC to the body
            // End the ordered list
            contents = String.Concat(contents, "</ol>");
            divTOC.InnerXml = contents;
            body.AppendChild(divTOC);

            // Append the selectedResults to the body
            body.AppendChild(divResults);
            return doc;
        }
    }
}
