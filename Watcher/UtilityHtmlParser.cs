// WATCHER
//
// UtilityHtmlParser.cs
// Main implementation of the HTML parsing functions and storage containers.
//
// Copyright (c) 2010 Casaba Security, LLC
// All Rights Reserved.
//
// Author: Chris Weber (chris@casaba.com)

using System;
using System.Diagnostics;
using System.Text;
using Fiddler;
using Majestic12;

namespace CasabaSecurity.Web.Watcher
{
    public class UtilityHtmlParser
    {
        #region Fields

        private HTMLparser parser;

        #endregion

        #region Ctor(s)

        public UtilityHtmlParser()
        {
        }
        #endregion

        #region Dtor(s)
        #endregion

        #region Public Properties

        public HTMLparser Parser
        {
            get { return parser; }
            set { parser = value; }
        }

        #endregion

        #region Public Method(s)

        public void Open(Session session)
        {

            String charset = "utf-8";
            Parser = new HTMLparser();

             try
            {
                if (Utility.IsResponseHtml(session) || Utility.IsResponseXml(session))
                {
                    Parser.Init(session.responseBodyBytes == null ? new byte[] { } : session.responseBodyBytes);
                    Parser.bAutoKeepScripts = true;
                    Parser.bEnableHeuristics = false;

                    // When bAutoExtractBetweenTagsOnly is false, the parser will see attributes
                    // in the script tags, such as <script src="mydata">.  Otherwise it will not.
                    Parser.bAutoExtractBetweenTagsOnly = true;

                }
            }
            catch (Exception e)
            {
                Trace.TraceWarning("Warning: UtilityHtmlParser threw an unhandled exception: {0}", e.Message);
                ExceptionLogger.HandleException(e);                
            }

            
           // Get the encoding name from the HTML or HTTP
           charset = Utility.GetHtmlCharset(session);

           try
             {
                 // TODO: check if the encoding is a known good before continuing!!!
                 // See if the charset name we got is a valid system encoding name.
               // GetEncoding should throw an Argument ex if not.
                 Encoding e = Encoding.GetEncoding(charset);
                 Parser.SetEncoding(charset);
             }
              catch (ArgumentException e)
             {
                 // Default to utf-8 if
                 Parser.SetEncoding(new UTF8Encoding(false,false));
             }
        }
        

        /// <summary>
        /// Cleanup and close the Parser.  MUST be called when you are done.
        /// </summary>
        public void Close()
        {
            Parser.Close();
        }
        public void Reset()
        {
            Parser.CleanUp();
            Parser.Reset();
        }


        #endregion

        #region Private Method(s)


        #endregion
    }
}
