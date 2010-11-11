// Casaba Watcher Team Foundation Export Adapter Plugin
// Copyright (c) 2010 Casaba Security, LLC.  All rights reserved.

using System;
using System.Collections.Generic;

namespace CasabaSecurity.Web.Watcher.TeamFoundation
{
    // TODO: include connection settings?
    internal partial class TeamFoundationConfiguration
    {
        /// <summary>
        /// This type represents translations of Watcher field values to field values used in other contexts.
        /// For example, the CasabaSecurity.Web.Watcher.Severity field displays "Informational", yet the TFS
        /// template only accepts entries similar to "4 - Low".  A translation might exist to map the Watcher
        /// field value to the TFS field value.
        /// </summary>
        public class TranslationEntry
        {
            /// <summary>
            /// Name of the Watcher field to translate. e.g., "CasabaSecurity.Web.Watcher.Severity"
            /// </summary>
            public String Field;

            /// <summary>
            /// The Key portion of this dictionary is the Watcher value. e.g., "Informational";
            /// The Value portion of this dictionary is the TFS value. e.g., "4 - Low".
            /// </summary>
            public Dictionary<String, String> TranslationTable = new Dictionary<string,string>();
        }

        /// <summary>
        /// This type represents the fields to be exported to a Team Foundation Server.
        /// </summary>
        public class FindingsMap
        {
            /// <summary>
            /// This is the type of work item. e.g., "Bug"
            /// </summary>
            public String Type;

            /// <summary>
            /// This is a list of mappings between Watcher and TFS; and may also define values which are
            /// always entered into a work item, i.e., via Destination and DefaultValue.
            /// </summary>
            public List<FindingMapEntry> Mappings = new List<FindingMapEntry>();

            /// <summary>
            /// This method resets the type properties to their original state.
            /// </summary>
            public void Reset()
            {
                Type = null;
                Mappings.Clear();
            }
        }

        /// <summary>
        /// This type represents a mapping from Watcher field to a TFS field; or TFS to a default value.
        /// </summary>
        public struct FindingMapEntry
        {
            public String Source;           // This is the Watcher source field
            public String Destination;      // This is the TFS destination field
            public String DefaultValue;     // This is the default value that will be used if Source is not specified
        }
    }
}
