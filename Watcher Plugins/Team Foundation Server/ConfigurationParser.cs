// Casaba Watcher Team Foundation Export Adapter Plugin
// Copyright (c) 2010 Casaba Security, LLC.  All rights reserved.

using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security;
using System.Text;
using System.Windows.Forms;
using System.Xml;
using System.Xml.Linq;
using Microsoft.TeamFoundation;
using Microsoft.TeamFoundation.Client;
using Microsoft.TeamFoundation.Common;
using Microsoft.TeamFoundation.WorkItemTracking.Client;
using CasabaSecurity.Web.Watcher.Collections;

namespace CasabaSecurity.Web.Watcher.TeamFoundation
{
    internal partial class TeamFoundationConfiguration
    {
        /// <summary>
        /// This method extracts the translation and mapping table from 
        /// the Watcher Team Foundation Adapter configuration.
        /// </summary>
        private void Parse()
        {
            // Obtain the root node
            XElement node = _configurationDocument.Element("WatcherTeamFoundationAdapter", StringComparison.OrdinalIgnoreCase);
            if (node == null)
            {
                Trace.TraceError("Error: Root node \"WatcherTeamFoundationAdapter\" not found.");
                throw new WatcherException("Error: Root node \"WatcherTeamFoundationAdapter\" not found.");
            }

            // Parse the name and value translation tables
            ParseValueTranslationTable(node);
            ParseNameTranslationTable(node);

            // Perform an initial validation of the entries in the table
            Validate();
        }

        /// <summary>
        /// This method parses the Watcher Value Translation table from the plugin configuration.
        /// </summary>
        /// <param name="root">The root node of the configuration.</param>
        private void ParseValueTranslationTable(XElement root)
        {
            // Search for a value translation node
            XElement valueTranslationElement = root.Element("ValueTranslation", StringComparison.OrdinalIgnoreCase);
            if (valueTranslationElement == null)
            {
                Trace.TraceInformation("Value translation table does not appear to exist.");
                return;
            }

            Trace.TraceInformation("Found the value translation table.");

            // Extract the fields whose values will be translated
            IEnumerable<XElement> watcherFields = valueTranslationElement.Elements("WatcherField", StringComparison.OrdinalIgnoreCase);
            foreach (XElement watcherField in watcherFields)
            {
                // Create a new translation instance, and store the name of the field to translate
                TranslationEntry entry = new TranslationEntry();
                entry.Field = watcherField.AttributeValue("Name", StringComparison.OrdinalIgnoreCase);
                
                // Extract the possible values of each field, and what value they should be translated to
                IEnumerable<XElement> watcherFieldValues = watcherField.Elements("Value", StringComparison.OrdinalIgnoreCase);
                foreach (XElement watcherFieldValue in watcherFieldValues)
                {
                    entry.TranslationTable.Add(
                        watcherFieldValue.AttributeValue("From", StringComparison.OrdinalIgnoreCase),
                        watcherFieldValue.AttributeValue("To", StringComparison.OrdinalIgnoreCase)
                    );
                }

                // Add the translation instance to the translation table
                this.Translation.Add(entry.Field, entry);
            }
        }

        /// <summary>
        /// This method parses the Watcher Field to Team Foundation Field table of the plugin configuration.
        /// </summary>
        /// <param name="root">The root node of the configuration.</param>
        private void ParseNameTranslationTable(XElement root)
        {
            // Search for the work item mapping node
            XElement workItemElement = root.Element("WorkItem", StringComparison.OrdinalIgnoreCase);
            if (workItemElement == null)
            {
                Trace.TraceError("Error: Element \"WorkItem\" not found.");
                return;
            }

            // Store the work item type, e.g., "Bug"
            this.ExportMap.Type = workItemElement.AttributeValue("Type", StringComparison.OrdinalIgnoreCase);

            // Obtain the nodes containing the field mappings and extract a list of
            // mapping objects based on the field mappings.
            IEnumerable<XElement> workItemFields = workItemElement.Elements("Field", StringComparison.OrdinalIgnoreCase);

            IEnumerable<FindingMapEntry> mapEntries =
                from field in workItemFields
                select new FindingMapEntry
                {
                    Source = field.ElementValue("WatcherSource", StringComparison.OrdinalIgnoreCase),
                    Destination = field.ElementValue("TeamFoundationDestination", StringComparison.OrdinalIgnoreCase),
                    DefaultValue = field.ElementValue("DefaultValue", StringComparison.OrdinalIgnoreCase)
                };

            // Add the field mapping entries read from the configuration to the configuration container.
            this.ExportMap.Mappings.AddRange(mapEntries);
        }

        /// <summary>
        /// Perform initial validation of the mappings prior to submitting the work item.
        /// </summary>
        /// <remarks>
        /// TODO: errors are currently not shown!
        /// </remarks>
        private void Validate()
        {
            // A work item type is always required
            if (this.ExportMap.Type == null)
            {
                String s = "Work item type not found.  Please specify the Type attribute on the WorkItem element.";
                Trace.TraceError(s);
                this.Errors.Add(s);
            }

            // Enumerate the mappings and ensure a destination; and source or default value is specified.
            for (int ndx = 0; ndx < this.ExportMap.Mappings.Count; ++ndx)
            {
                FindingMapEntry e = this.ExportMap.Mappings[ndx];

                // Destination field is always required.
                if (e.Destination == null)
                {
                    String s = String.Format("Work item field mapping #{0} is not valid.  Please specify a destination field.", ndx);
                    Trace.TraceError(s);
                    this.Errors.Add(s);
                    continue;
                }

                // Source field or default value is required, given a destination.
                // i.e., they cannot both be non-existent.
                if (e.Source == null && e.DefaultValue == null)
                {
                    String s = String.Format("Work item field mapping #{0} is not valid.  Please specify a source or default value.", ndx);
                    Trace.TraceError(s);
                    this.Errors.Add(s);
                    continue;
                }
            }
        }
    }
}
