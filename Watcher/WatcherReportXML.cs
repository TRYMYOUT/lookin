using System;
using System.IO;
using System.Collections.Generic;
using System.Text;
using System.Xml;
using System.Threading;
using System.Windows.Forms;
using CasabaSecurity.Web.Watcher.Collections;

namespace CasabaSecurity.Web.Watcher
{
    public class WatcherReportXML : WatcherOutputPlugin
    {
        public WatcherReportXML()
        {
        }

        public override String GetName()
        {
            return "XML Report";
        }

        public override String GetDescription()
        {
            return String.Empty;
        }

        public override Panel GetConfigPanel()
        {
            return null;
        }

        public override bool GetExportDefaults(ref String defaultFilename, ref String defaultFilter)
        {
            defaultFilename = "watcher.xml";
            defaultFilter = "XML File (*.xml)|*.xml";
            return true;
        }

        public override Stream SaveResult(WatcherResultCollection resultslist)
        {
            // Reset the bar's progress position
            WatcherEngine.ProgressDialog.ProgressValue = 0;
            WatcherEngine.ProgressDialog.MaximumRange = resultslist.Count;
            WatcherEngine.ProgressDialog.MinimumRange = 0;
            WatcherEngine.ProgressDialog.Increment = 1;
            WatcherEngine.ProgressDialog.BodyText = "Exporting results to XML:";

            MemoryStream s = new MemoryStream();
            XmlDocument doc = GetXmlReport(resultslist);

            if (doc != null)
            {
                doc.Save(s);
                return s;
            }

            return null;
        }

        private XmlDocument GetXmlReport(WatcherResultCollection resultslist)
        {
            XmlDocument doc = new XmlDocument();
            XmlDeclaration xmlDec;
            XmlElement root = doc.DocumentElement;
            XmlElement issue = null;
            XmlElement level = null;
            XmlElement url = null;
            XmlElement type = null;
            XmlElement desc = null;

            // Get current Watcher version
            Version currentver = new UpdateManager().CurrentVersionEngine;

            // Create the very beginning Xml Declaration
            xmlDec = doc.CreateXmlDeclaration("1.0", "utf-8", null);
            root = doc.CreateElement("watcher");

            root.SetAttribute("version", currentver.ToString());
            root.SetAttribute("date", DateTime.Today.ToLongDateString());
            root.SetAttribute("originDomain", WatcherEngine.Configuration.OriginDomain.ToString());
            root.SetAttribute("trustedDomains", WatcherEngine.Configuration.GetTrustedDomainsAsString());
            root.SetAttribute("enabledChecks", WatcherEngine.CheckManager.GetEnabledChecksAsString());
           
            doc.AppendChild(root);

            doc.InsertBefore(xmlDec, root);

            foreach (WatcherResult item in resultslist)
            {
                WatcherEngine.ProgressDialog.labelOperation.Text = "Saving Finding: " + item.Title;
                WatcherEngine.ProgressDialog.UpdateProgress();

                issue = doc.CreateElement("issue");
                level = doc.CreateElement("level");

                level.InnerText = item.Severity.ToString();

                url = doc.CreateElement("url");

                url.InnerText = item.URL;

                type = doc.CreateElement("type");

                type.InnerText = item.Title;

                desc = doc.CreateElement("description");

                desc.InnerText = item.Description;

                issue.AppendChild(type);
                issue.AppendChild(level);
                issue.AppendChild(url);
                issue.AppendChild(desc);

                root.AppendChild(issue);
            }

            return doc;
        }
    }
}
