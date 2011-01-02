// WATCHER
//
// UtilityHtmlParser.cs
// Main implementation of the HTML parsing functions and storage containers.
//
// Copyright (c) 2010 Casaba Security, LLC
// All Rights Reserved.
//
// Author: Chris Weber (chris@casabasecurity.com)

using System;
using System.Collections.Generic;
using System.Collections;
using System.Text;
using Fiddler;
using Majestic12;

namespace CasabaSecurity.Web.Watcher
{
    public class UtilityHtmlParser
    {
        #region Fields
        private static Char[] whitespace = { ' ', '\r', '\n', '\t' }; 
        private HTMLparser parser;

        #endregion

        #region Ctor(s)

        public UtilityHtmlParser() 
        {
        }

        /// <summary>
        /// Initialize a new instance of the Majestic12 HTMLParser.  
        /// MUST call Close() when finished.
        /// </summary>
        /// <param name="session">The session to be parsed.</param>
        public UtilityHtmlParser(Session session)
        {
            String charset = String.Empty;
            Parser = new HTMLparser();
            if (Utility.IsResponseHtml(session) || Utility.IsResponseXml(session))
            {
                Parser.Init(session.responseBodyBytes == null ? new byte[] { } : session.responseBodyBytes);
                // Set the encoding charset
                charset = Utility.GetHtmlCharset(session);
                Parser.SetEncoding(charset);
                Parser.bAutoKeepScripts = true;
                Parser.bEnableHeuristics = false;

                // When bAutoExtractBetweenTagsOnly is false, the parser will see attributes
                // in the script tags, such as <script src="mydata">.  Otherwise it will not.
                Parser.bAutoExtractBetweenTagsOnly = true;

            }
        }

        #endregion

        #region Public Properties

        public HTMLparser Parser
        {
            get { return parser; }
            set { parser = value; }
        }
        
        #endregion

        #region Public Method(s)

        /// <summary>
        /// Cleanup and close the Parser.  MUST be called when you are done.
        /// </summary>
        public void Close()
        {
            Parser.CleanUp();
            Parser.Close();
        }


        #endregion

        #region Private Method(s)


        #endregion
    }
}
