// WATCHER
//
// UtilityHtmlParser.cs
// Main implementation of the HTML parsing functions and storage containers, 
// using the HtmlAgilityPack.
//
// Copyright (c) 2010 Casaba Security, LLC
// All Rights Reserved.
//
// Author: Chris Weber (chris@casabasecurity.com)

using System;
using System.Collections.Generic;
using System.Collections;
using System.Diagnostics;
using System.IO;
using System.Text;
using Fiddler;
using HtmlAgilityPack;
using System.Linq;

namespace CasabaSecurity.Web.Watcher
{
    public class UtilityHtmlDocument
    {
        #region Fields
        private HtmlDocument _document = new HtmlDocument();
        private IList<HtmlNode> _nodes;
        #endregion Fields

        #region Ctor(s)
        public UtilityHtmlDocument()
        {
        }

        public UtilityHtmlDocument(Session session) 
        {
            String charset = String.Empty;
            if (Utility.IsResponseHtml(session) || Utility.IsResponseXml(session))
            {
                // Get the encoding charset to set
                charset = Utility.GetHtmlCharset(session);
                // Put the source HTML into a stream
                Stream html = new MemoryStream(session.responseBodyBytes);
                // Prepare an encoding with the charset we figured out above

                Encoding enc = Encoding.UTF8;

                try
                {
                    enc = Encoding.GetEncoding(charset);

                }
                // Default to UTF-8 if an illegal encoding name was used.
                catch (ArgumentException e)
                {
                    Trace.TraceWarning("Warning: Watcher Encoding object threw an unhandled exception: {0}", e.Message);
                    ExceptionLogger.HandleException(e);
                    enc = Encoding.UTF8;
                }

                // Setup the document to not close certain tags that can come unclosed, for example:
                // <img src=""></img> is usually <img src="#" />
                if (HtmlNode.ElementsFlags.ContainsKey("domain"))
                {
                    HtmlNode.ElementsFlags["domain"] = HtmlElementFlag.Empty | HtmlElementFlag.Closed;
                }
                else
                {
                    HtmlNode.ElementsFlags.Add("domain", HtmlElementFlag.Empty | HtmlElementFlag.Closed);
                }

                // Setup the Document to ignore stated encodings in the HTML, otherwise errors will throw for mistyped
                // or otherwise unknown encodings.
                Document.OptionReadEncoding = false;
                Document.OptionCheckSyntax = false;
                Document.OptionOutputAsXml = false;

                // Load the source HTML into the document model
                Document.Load(html, enc);
                
                // Parse all HTML nodes from the document into a list
                // prepared for consumers.
                Nodes = Document.DocumentNode.DescendantNodes().ToList();

                // Check for parsing errors
                if (Document.ParseErrors.Count() > 0)
                {
                    // Do something if needed.
                }
            }
        }
        #endregion

        #region Public Properties
        public HtmlDocument Document
        {
            get { return _document; }
            set { _document = value; }
        }
        public IList<HtmlNode> Nodes
        {
            get { return _nodes; }
            set { _nodes = value; }
        }
        #endregion

    }
}
