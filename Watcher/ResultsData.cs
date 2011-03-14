// WATCHER
//
// AlertData.cs
// Implements a disconnected, in-memory database of Alerts.
//
// Copyright (c) 2010 Casaba Security, LLC
// All Rights Reserved.
//
using System;
using System.Collections.Generic;
using System.Linq;
using System.Data;
using System.Text;

namespace CasabaSecurity.Web.Watcher
{
    public static class ResultsData
    {

        // Find a place to create an instance of this class
        // start adding data
        private static DataSet resultsDataSet = new DataSet("ResultsData");
        private static DataTable resultsDataTable = new DataTable("Results");

        #region Ctor(s)
        //public ResultsData()
        //{
        //    BuildTable();
        //}
        #endregion

        // TODO: Is this safe?
        public static DataSet ResultsDataSet
        {
            get
            {
                lock (resultsDataSet)
                {
                   return resultsDataSet; 
                }
            }
        }

        public static void BuildTable()
        {
            // Don't build the table if it already exists

            if (resultsDataSet.ExtendedProperties.ContainsKey("Initialized"))
            {
                return;
            }

            // Create the table schema to map to the result class
            DataColumn colId = new DataColumn("Id",typeof(Int32));
            // Column Id gives us a unique ID for each record
            colId.AutoIncrement = true;
            DataColumn colSessionId = new DataColumn("SessionId", typeof(Int32));
            DataColumn colSev = new DataColumn("Severity",typeof(Int32));
            DataColumn colUrl = new DataColumn("Url",typeof(String));
            DataColumn colName = new DataColumn("Name",typeof(String));
            DataColumn colDesc = new DataColumn("Description", typeof(String));
            DataColumn colCount = new DataColumn("Count",typeof(Int32));
            DataColumn colRef = new DataColumn("Reference",typeof(String));
            resultsDataTable.Columns.AddRange(new DataColumn[] { colId, colSessionId,colSev,colUrl,colName,colDesc,colCount,colRef});

            // Add the table to the dataset
            resultsDataSet.Tables.Add(resultsDataTable);

            resultsDataSet.ExtendedProperties["TimeStamp"] = DateTime.UtcNow;
            resultsDataSet.ExtendedProperties["Initialized"] = true;
        }

        public static void AddResult(Result result )
        {
            // Build a row and add it
            DataRow row = resultsDataTable.NewRow();
            row["Id"] = result.Id;
            row["Severity"] = result.Severity;
            row["Url"] = result.URL;
            row["Name"] = result.TypeX;
            row["Description"] = result.Description;
            row["Count"] = result.AlertCount;
            row["Reference"] = result.refLink;
            resultsDataTable.Rows.Add(row);
        }

    }

    public class Result
    {
        #region Fields
        private Int32 _id;
        private WatcherResultSeverity _severity;
        private String _url;
        private String _name;
        private String _description;
        private Int32 _count;
        private WatcherCheckStandardsCompliance _compliance;
        private String _reflink;
        #endregion

        #region Ctor(s)

        public Result(WatcherResultSeverity severity, Int32 id, String name, String url, String description, int count)
            : this(severity, id, name, url, description, count, WatcherCheckStandardsCompliance.None, String.Empty) { }

        public Result(WatcherResultSeverity severity, Int32 id, String name, String url, String description, int count, WatcherCheckStandardsCompliance compliance, String reflink)
        {
            _id = id;
            _severity = severity;
            _url = url;
            _name = name;
            _description = description;
            _count = count;
            _compliance = compliance;
            _reflink = reflink;

            // Set the item text to the canonical version of the WatcherResutlSeverity
            //this.Text = severity.ToString();
        }
        #endregion

        #region Public Properties

        public WatcherResultSeverity Severity
        {
            get { return _severity; }
        }

        public Int32 AlertCount
        {
            get { return _count; }
        }

        public Int32 Id
        {
            get { return _id; }
        }

        public String URL
        {
            get { return _url; }
        }

        public String TypeX
        {
            get { return _name; }
        }

        public String Description
        {
            get { return _description; }
        }

        public WatcherCheckStandardsCompliance Compliance
        {
            get { return _compliance; }
        }

        public String refLink
        {
            get { return _reflink; }
        }

        #endregion

        #region Public Method(s)

        public override String ToString()
        {
            string output = "";
            output = output + Severity.ToString() + "\t"
                    + this.Id + "\t"
                    + this.TypeX + "\t"
                    + this.URL + "\r\n";
            return output;
        }

        public override bool Equals(Object obj)
        {
            Result result = null;

            if (obj is Result)
            {
                result = (Result)obj;

                if (result.Severity == this.Severity && result.URL == this.URL && result.TypeX == this.TypeX && result.Description == this.Description)
                {
                    return (true);
                }

                return (false);
            }

            return base.Equals(obj);
        }

        public override int GetHashCode()
        {
            return base.GetHashCode();
        }

        #endregion

    }
}
