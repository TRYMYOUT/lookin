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
            colId.Unique = true;
            DataColumn colSessionId = new DataColumn("SessionId", typeof(Int32));
            DataColumn colSev = new DataColumn("Severity",typeof(Int32));
            DataColumn colUrl = new DataColumn("Url",typeof(String));
            DataColumn colName = new DataColumn("Name",typeof(String));
            DataColumn colDesc = new DataColumn("Description", typeof(String));
            DataColumn colCount = new DataColumn("Count",typeof(Int32));
            DataColumn colRef = new DataColumn("Reference",typeof(String));
            resultsDataTable.Columns.AddRange(new DataColumn[] { colId, colSessionId,colSev,colUrl,colName,colDesc,colCount,colRef});

            // Set the primary key 
            DataColumn[] keys = new DataColumn[1];
            keys[0] = colId;
            resultsDataTable.PrimaryKey = keys;
            // Add the table to the dataset
            resultsDataSet.Tables.Add(resultsDataTable);

            resultsDataSet.ExtendedProperties["TimeStamp"] = DateTime.UtcNow;
            resultsDataSet.ExtendedProperties["Initialized"] = true;
        }

        /// <summary>
        /// Build a Row and add it to the database.
        /// </summary>
        /// <param name="result"></param>
        public static void AddResult(Result result )
        {
            // Check if the result is unique and doesn't already exist in the database.
            // Don't even create a row object until we know it's unique, otherwise
            // the unique 'Id' column will have its value auto-incremented and results 
            // will be off.

            if (IsResultUnique(result))
            {
                resultsDataTable.BeginLoadData();
                DataRow row = resultsDataTable.NewRow();
                row["SessionId"] = result.SessionId;
                row["Severity"] = result.Severity;
                row["Url"] = result.URL;
                row["Name"] = result.TypeX;
                row["Description"] = result.Description;
                row["Count"] = result.AlertCount;
                row["Reference"] = result.refLink;

                resultsDataTable.Rows.Add(row);

                resultsDataTable.AcceptChanges();
                resultsDataTable.EndLoadData();
            }

        }

        private static bool IsResultUnique(Result result)
        {
            if (resultsDataTable.Rows != null)
                foreach (DataRow row in resultsDataTable.Rows)
                {
                    if (row["Url"].ToString() == result.URL &&
                        row["Description"].ToString() == result.Description)
                    {
                        return false;
                    }
                }
            return true;
        }

        public static string GetResultDescription(Int32 id)
        {
            return resultsDataTable.Rows[id]["Description"].ToString();
        }

        public static string GetResultReferenceLink(Int32 id)
        {
            return resultsDataTable.Rows[id]["Reference"].ToString();
        }

        public static Int32 GetResultSessionId(Int32 id)
        {
            return (Int32)resultsDataTable.Rows[id]["SessionId"];
        }

    }

    public class Result
    {
        #region Fields
        private Int32 _sessionId;
        private WatcherResultSeverity _severity;
        private String _url;
        private String _name;
        private String _description;
        private Int32 _count;
        private WatcherCheckStandardsCompliance _compliance;
        private String _reflink;
        #endregion

        #region Ctor(s)

        public Result(WatcherResultSeverity severity, Int32 sessionId, String name, String url, String description, int count)
            : this(severity, sessionId, name, url, description, count, WatcherCheckStandardsCompliance.None, String.Empty) { }

        public Result(WatcherResultSeverity severity, Int32 sessionId, String name, String url, String description, int count, WatcherCheckStandardsCompliance compliance, String reflink)
        {
            _sessionId = sessionId;
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

        public Int32 SessionId
        {
            get { return _sessionId; }
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
                    + this.SessionId + "\t"
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
