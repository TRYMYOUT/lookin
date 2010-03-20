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

        // STORAGE CONTAINERS
        //
        // Note: We can store HTML text, tags, and attributes in a variety of ways
        //       for checks to access.
        //
        // Store a list of all the text in the HTML.  Text is the stuff between tags.
        // e.g. <title>this stuff is text</title>
        private List<String> htmlTextCollection;

        // Store a list of all the javascript found in the HTML.  This doesn't get parsed
        // so we end up collecting everything between the script tags.
        private List<String> htmlScriptCollection;

        // Store a list of all the text in the HTML.  Text is the stuff between tags.
        // e.g. <title>this stuff is text</title>
        private List<String> htmlAttributeValues;

        // Store a Dictionary of all the attribute names/values.  All values are keyed 
        // by the attribute name.  The List<String> will be a collection of attribute
        // values stored in htmlAttributeValues.
        private Dictionary<String, List<String>> htmlAttributeCollection;

        // Store a Dictionary of all tags, keyed by tag name, and containing the
        // dictionary collection of attribute names/values.
        private List<HtmlElement> htmlElementCollection;
        #endregion

        #region Ctor(s)

        public UtilityHtmlParser()
        {
        }

        public UtilityHtmlParser(Session session)
        {
            String charset = String.Empty;
            Parser = new HTMLparser();
            if (Utility.IsResponseHtml(session))
            {
                Parser.Init(session.responseBodyBytes == null ? new byte[] { } : session.responseBodyBytes);

                // Set the encoding charset
                charset = Utility.GetHtmlCharset(session);
                Parser.SetEncoding(charset);
                Parser.bAutoKeepScripts = true;

                // When bAutoExtractBetweenTagsOnly is false, the parser will see attributes
                // in the script tags, such as <script src="mydata">.  Otherwise it will not.
                Parser.bAutoExtractBetweenTagsOnly = true;

                // Initialize the storage objects
                HtmlElementCollection = new List<HtmlElement>();
                HtmlAttributeCollection = new Dictionary<String, List<String>>();
                HtmlTextCollection = new List<String>();
                HtmlScriptCollection = new List<String>();

                // Parse the HTML
                ParseAllHtml();
            }
            Parser.CleanUp();
            Parser.Close();
        }

        #endregion

        #region Public Properties

        public HTMLparser Parser
        {
            get { return parser; }
            set { parser = value; }
        }
        
        /// <summary>
        /// A collection of all HTML element's attribute values in the page.  
        /// This is just a list of the attribute values.
        /// e.g.  In this HTML fragment only 'value' would be stored
        ///       &lt;a href="value"&gt;
        /// </summary>
        public List<String> HtmlAttributeValues
        {
            get { return htmlAttributeValues; }
            set { htmlAttributeValues = value; }
        }

        /// <summary>
        /// A collection of all attrbute name/value pairs in the page.
        /// e.g. In this HTML fragment only 'href=value' would be stored.
        ///      &lt;a href="value"&gt;
        /// </summary>
        public Dictionary<String,List<String>> HtmlAttributeCollection
        {
            get { return htmlAttributeCollection; }
            set { htmlAttributeCollection = value; }
        }

        /// <summary>
        /// A collection of all the HTML element tags in the page with their attributes and values, e.g. <html>, <a>, etc.
        /// </summary>
        public List<HtmlElement> HtmlElementCollection
        {
            get { return htmlElementCollection; }
            set { htmlElementCollection = value; }
        }

        /// <summary>
        /// A collection of all non-markup text in the page.  
        /// e.g.  In the following HTML fragment, 'plain text' would be stored.
        ///       &lt;div&gt;plain text&lt;/div&gt;
        /// </summary>
        public List<String> HtmlTextCollection
        {
            get { return htmlTextCollection; }
            set { htmlTextCollection = value; }
        }

        /// <summary>
        /// A collection of all script blocks and their content.
        /// e.g. The following script block
        /// </summary>
        public List<String> HtmlScriptCollection
        {
            get { return htmlScriptCollection; }
            set { htmlScriptCollection = value; }
        }

        #endregion

        #region Public Method(s)

        public void ParseAllHtml()
        {
            HTMLchunk chunk;
            String tag = String.Empty;
            String key = String.Empty;
            String value = String.Empty;

            try
            {
                // Parse a chunk of HTML, a chunk being a start tag, end tag, or what's between tags.
                while ((chunk = parser.ParseNext()) != null)
                {
                    // I don't care to create this until I know we have some
                    // attributes we'd want to look at.
                    HtmlElement element = new HtmlElement();
                    List<String> attList = new List<String>();
                    Dictionary<String, List<String>> attColl = new Dictionary<String, List<String>>();

                    switch (chunk.oType)
                    {
                        case HTMLchunkType.OpenTag:
                            
                            // Collect the attribute names and values.
                            if (chunk.iParams > 0)
                            {
                                tag = chunk.sTag;

                                foreach (DictionaryEntry de in chunk.oParams)
                                {
                                    key = de.Key.ToString();
                                    value = de.Value.ToString();
                                    value = value.Trim(whitespace);
                                    BuildCollections(tag, key, value, element, attList, attColl);
                                }
                            }
                            break;

                        case HTMLchunkType.Text:
                            
                            // Collect the text from the HTML,
                            // but don't collect null, empty, or whitespace HTML chunks.
                            if (!String.IsNullOrEmpty(chunk.oHTML) && chunk.oHTML != " ")
                            {
                                // Don't add the value if it already exists.
                                if (!HtmlTextCollection.Contains(chunk.oHTML.Trim(whitespace)))
                                {
                                    HtmlTextCollection.Add(chunk.oHTML.Trim(whitespace));
                                }
                            }
                            break;

                        case HTMLchunkType.Script:
                            
                            // Collect the Javascript from the HTML,
                            // but don't collect null, empty, or whitespace HTML chunks.
                            if (!String.IsNullOrEmpty(chunk.oHTML) && chunk.oHTML != " ")
                            {
                                // Build the script collection, but don't add the value if it already exists.
                                if (!HtmlScriptCollection.Contains(chunk.oHTML.Trim(whitespace)))
                                {
                                    HtmlScriptCollection.Add(chunk.oHTML.Trim(whitespace));
                                }

                                // Collect the attribute names and values.
                                if (chunk.iParams > 0)
                                {
                                    tag = chunk.sTag;

                                    foreach (DictionaryEntry de in chunk.oParams)
                                    {
                                        key = de.Key.ToString();
                                        value = de.Value.ToString();
                                        value = value.Trim(whitespace);
                                        BuildCollections(tag, key, value, element, attList, attColl);
                                    }
                                }
                            }
                            break;

                        default:
                            break;
                    }
                }
            }

            catch (Exception e)
            {
                String error = e.Message;
            }
        }

        #endregion

        #region Private Method(s)

        private void BuildCollections(String tag, String key, String value, HtmlElement element, List<String> attList, Dictionary<String, List<String>> attColl)
        {
            if (!String.IsNullOrEmpty(value))
            {
                if (attColl.ContainsKey(key))
                {
                    attList = attColl[key];
                    attList.Add(value);
                }
                else
                {
                    attList = new List<String>();
                    attList.Add(value);
                    attColl.Add(key, attList);
                }
                element.tag = tag;
                element.att = attColl;
        
                // Don't add duplicate elements
                if (!HtmlElementCollection.Contains(element))
                {
                    HtmlElementCollection.Add(element);
                }
            }
        }

        #endregion
    }

    /// <summary>
    /// A structure to hold an HTML element tag name (e.g. a, img, form, script) and its 
    /// associated Dictionary of attribute name/value pairs.
    /// </summary>
    public struct HtmlElement
    {
        public String tag;
        public Dictionary<String, List<String>> att;
    }
}
