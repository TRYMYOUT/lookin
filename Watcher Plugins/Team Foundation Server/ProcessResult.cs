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

using CasabaSecurity.Web.Watcher;
using CasabaSecurity.Web.Watcher.Collections;

namespace CasabaSecurity.Web.Watcher.TeamFoundation
{
    public partial class TeamFoundationOutputPlugin : WatcherOutputPlugin
    {
        #region Private Method(s)

        /// <summary>
        /// This method exports a single item.
        /// </summary>
        /// <remarks>TODO: Standards Compliance Handling?</remarks>
        private void ExportResult(WatcherResult watcherResult)
        {
            WatcherEngine.ProgressDialog.UpdateProgress("Verifying work item type...");

            // Verify the work item type exists in the project (e.g., "Bug")
            if (_adapter.Project.WorkItemTypes.Contains(_adapter.Configuration.ExportMap.Type) == false)
            {
                String s = String.Format("Required work item \"{0}\" does not exist in the work item template.", _adapter.Configuration.ExportMap.Type);
                Trace.TraceError(s);
                throw new WatcherException(s); // TODO: Message box title: Error
            }

            // Create an instance of the work item
            WatcherEngine.ProgressDialog.UpdateProgress(String.Format("Creating work item \"{0}\"...", watcherResult.Title));
            WorkItem workItem = new WorkItem(_adapter.Project.WorkItemTypes[_adapter.Configuration.ExportMap.Type]);

#if DEBUG
            Debug.WriteLine(String.Format("Work item \"{0}\" fields:", workItem.Title));
            foreach (Field field in workItem.Fields)
            {
                Debug.WriteLine(String.Format("\tRequired: {0}; Reference Name: {1}", field.IsRequired, field.ReferenceName));
            }
#endif

            // Ensure fields required by the work item template have been defined in the XML map
            try { ValidateWorkItemFields(workItem); }
            catch (WatcherException ex)
            {
                String s = String.Format("Unable to validate work item fields:\r\n\r\n{0}", ex.Message);
                Trace.TraceError(s);
                throw new WatcherException(s, ex); // TODO: Message box title: Error
            }

            // Map the Watcher result information to the TFS template (including SDL fields)
            try { PopulateWorkItem(workItem, watcherResult); }
            catch (WatcherException ex)
            {
                String s = String.Format("Unable to populate work item fields:\r\n\r\n{0}", ex.Message);
                Trace.TraceError(s);
                throw new WatcherException(s, ex); // TODO: Message box title: Error
            }

            WatcherEngine.ProgressDialog.UpdateProgress("Saving work item...");

            // Save the new work item
            // TODO: Allow the user to continue on non-fatal failures
            try { workItem.Save(); }
            catch (ValidationException ex)
            {
                String s = String.Format("Unable to save the work item template:\r\n\r\n{0}", ex.Message);
                Trace.TraceError(s);
                throw new WatcherException(s, ex);  // TODO: Message box title: Error
            }
        }

        /// <summary>
        /// This method maps Watcher fields to SDL fields.
        /// </summary>
        /// <remarks>
        /// TODO: Mappings should be pulled from the user-configurable XML file.
        /// TODO: Description should be converted to HTML and include the URI.
        /// TODO: Mappings should work even if the configuration file does not exist.
        /// </remarks>
        /// <param name="workItem">The TFS work item.</param>
        /// <param name="watcherResult">The Watcher finding.</param>
        private void PopulateWorkItem(WorkItem workItem, WatcherResult watcherResult)
        {
            // Set defaults
            //
            // Set the origin to "Watcher"
            if (workItem.Fields.Contains("Microsoft.SDL.Security.Origin"))      // TODO: optimize. use single string
            {
                workItem["Microsoft.SDL.Security.Origin"] = "Watcher Web Security Tool (Casaba Security, LLC.)";
            }

            // Set the title of the work item.
            //
            // If the configuration contains a destination entry of System.Title and is sourced by
            // the CasabaSecurity.Watcher.Title, use a Watcher-default title.  If the source does
            // not exist, use the default value specified in the configuration.
            //
            foreach (TeamFoundationConfiguration.FindingMapEntry entry in _adapter.Configuration.ExportMap.Mappings)
            {
                // TODO: This is the case where source and destination are specified
                // TODO: Case 2: Where destination and default value are specified
                Debug.Assert(entry.Destination != null, "Destination must always be specified in the mapping.");
                if (entry.Destination == null)
                {
                    Trace.TraceError("TeamFoundationMapEntry contains a destination that is null.  This should never happen.");
                    throw new WatcherException("TeamFoundationMapEntry contains a destination that is null."); // TODO: review
                }

                // The destination field name must exist in the work item
                // TODO: this should have already been checked
                if (workItem.Fields.Contains(entry.Destination) == false)
                {
                    Trace.TraceError("Destination name does not exist in the work item template."); // TODO: single string
                    throw new WatcherException("Destination name does not exist in the work item template."); // TODO: be more descript
                }

                // XXX Enumerate each source, if it matches one we know about, add our version of the value to the field.
                // XXX Otherwise, if there is no match, it's an error.
                // XXX TODO: what if this is null?
                switch (entry.Source)
                {
                    case "CasabaSecurity.Web.Watcher.Title":
                        workItem[entry.Destination] = String.Format("{0}", watcherResult.Title);
                        break;

                    // TODO: The Watcher description should be translated to HTML prior to setting this field.
                    case "CasabaSecurity.Web.Watcher.Description":
                        workItem[entry.Destination] = watcherResult.Description;
                        break;

                    case "CasabaSecurity.Web.Watcher.Origin":
                        workItem[entry.Destination] = "Watcher Web Security Tool (Casaba Security, LLC.)";
                        break;

                    case "CasabaSecurity.Web.Watcher.Severity":
                        workItem[entry.Destination] = _adapter.Configuration.GetTranslatedValue("CasabaSecurity.Web.Watcher.Severity", watcherResult.Severity.ToString()); //XXX TODO
                        break;

                    // If no source field exists for this destination, use the default value defined in the mapping
                    default:
                        // TODO: ensure when reading mapping that the above fields are the only valid fields
                        // TODO: ensure that only source/destination and destination/default value pairs are specified.
                        // TODO: ensure DefaultValue is not null?
                        workItem[entry.Destination] = entry.DefaultValue;
                        break;
                }
            }
        }

        /// <summary>
        /// This method ensures the fields required by the Work Item Template have been defined in the XML map.
        /// </summary>
        /// <param name="workItem">The Team Foundation work item whose fields are to be examined.</param>
        private void ValidateWorkItemFields(WorkItem workItem)
        {
            foreach (Field field in workItem.Fields)
            {
                // If the WIT field is required and does not have a default value
                // TODO: ensure the values were are submitting are of the correct type and enumeration
                // TODO: unsure about not requiring date times.  System.CreatedDate seems to be required but is not labeled as such in the WIT.
                if (field.IsRequired && field.FieldDefinition.FieldType != FieldType.DateTime && field.Value == null)
                {
                    Boolean mapContainsRequiredField = false;

                    // Enumerate the entries in the map and search for the required field
                    foreach (TeamFoundationConfiguration.FindingMapEntry mapEntry in _adapter.Configuration.ExportMap.Mappings)
                    {
                        // The destination comes from the XML file defining the mapping, and the
                        // Reference Name is the fully-qualified field name of the destination.
                        if (mapEntry.Destination == field.ReferenceName)
                        {
                            mapContainsRequiredField = true;
                            break;
                        }
                    }

                    // Required field was not found
                    if (mapContainsRequiredField == false)
                    {
                        String s = String.Format("Required field \"{0}\" does not exist in the Watcher Team Foundation Configuration file.", field.ReferenceName);
                        Trace.TraceError(s);
                        throw new WatcherException(s);
                    }
                }
            }

            List<String> warnings = new List<String>();

            // Make sure destination fields specified in the XML file exist in the Work Item Template.
            foreach (TeamFoundationConfiguration.FindingMapEntry mapEntry in _adapter.Configuration.ExportMap.Mappings)
            {
                if (workItem.Fields.Contains(mapEntry.Destination) == false)
                {
                    // WIT does not contain a field defined in the XML
                    String s = String.Format("Field '{0}' does not exist in Team Foundation Server Work Item Template '{1}'.  Please ensure the field is spelled correctly in the Team Foundation configuration file, or remove it altogether.", mapEntry.Destination, workItem.Project.Name);
                    Trace.TraceWarning(s);
                    warnings.Add(s);
                }
            }

            // If there are warnings, display them.      // TODO: make sure the operation is allowed to continue
            if (warnings.Count > 0)
            {
                // Create the display string
                StringBuilder sb = new StringBuilder(warnings.Count);
                foreach (String s in warnings)
                {
                    sb.AppendFormat("{0}\r\n\r\n", s);
                }
                throw new WatcherException(sb.ToString());
            }
        }

        #endregion
    }
}
