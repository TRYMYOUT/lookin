using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml.Linq;

namespace CasabaSecurity.Web.Watcher.TeamFoundation
{
    /// <summary>
    /// This class implements extention methods for LINQ to XML types which provide
    /// the ability to specify a string comparison type when searching for element
    /// and attribute names and values in XML.  This is particularly useful if you'd 
    /// like to ignore case in an XML document.
    /// </summary>
    static class XDocumentExtensions
    {
        /// <summary>
        /// This method returns a list of elements matching the specified name, using the specified string comparison method.
        /// </summary>
        /// <param name="container">The XML container instance.</param>
        /// <param name="name">The name of the element to locate.</param>
        /// <param name="comparisonType">One of the System.StringComparison values.</param>
        /// <returns>List of elements matching the specified name.</returns>
        public static IEnumerable<XElement> Elements(this XContainer container, XName name, StringComparison comparisonType)
        {
            foreach (XElement element in container.Elements())
            {
                if (String.Compare(element.Name.LocalName, name.LocalName, comparisonType) == 0)
                {
                    yield return element;
                }
            }
        }

        /// <summary>
        /// This method returns the first element matching the specified name, using the specified comparison method,
        /// in document order.
        /// </summary>
        /// <param name="container">The XML container instance.</param>
        /// <param name="name">The name of the element to locate.</param>
        /// <param name="comparisonType">One of the System.StringComparison values.</param>
        /// <returns>An XML element matching the specified name or null if the element doesn't exist.</returns>
        public static XElement Element(this XContainer container, XName name, StringComparison comparisonType)
        {
            foreach (XElement element in container.Elements())
            {
                if (String.Compare(element.Name.LocalName, name.LocalName, comparisonType) == 0)
                {
                    return element;
                }
            }

            return null;
        }

        /// <summary>
        /// This method returns the value of the specified element or null if the element does not exist.
        /// </summary>
        /// <param name="container">The XML container instance.</param>
        /// <param name="name">The name of the element to locate.</param>
        /// <param name="comparisonType">One of the System.StringComparison values.</param>
        /// <returns>The element matching the specified name or null if the element doesn't exist.</returns>
        public static String ElementValue(this XContainer container, XName name, StringComparison comparisonType)
        {
            XElement element = container.Element(name, comparisonType);
            return element == null ? null : element.Value;
        }

        /// <summary>
        /// This method returns the value of the specified element.
        /// </summary>
        /// <remarks>TODO: Currently unused.</remarks>
        /// <param name="container">The XML container instance.</param>
        /// <param name="name">The name of the element to locate.</param>
        /// <returns>An XML element matching the specified name or null if the element doesn't exist.</returns>
        public static String ElementValue(this XContainer container, XName name)
        {
            return container.ElementValue(name, StringComparison.CurrentCulture);
        }

        /// <summary>
        /// This method returns the first attribute matching the specified name, using the specified comparison method,
        /// in document order.
        /// </summary>
        /// <param name="element">The XML container instance.</param>
        /// <param name="name">The name of the element to locate.</param>
        /// <param name="comparisonType">One of the System.StringComparison values.</param>
        /// <returns>The attribute matching the specified name or null if the attribute doesn't exist.</returns>
        public static XAttribute Attribute(this XElement element, XName name, StringComparison comparisonType)
        {
            foreach (XAttribute attr in element.Attributes())
            {
                if (String.Compare(attr.Name.LocalName, name.LocalName, comparisonType) == 0)
                {
                    return attr;
                }
            }

            return null;
        }

        /// <summary>
        /// This method returns the first value of the attribute matching the specified name, using the specified comparison type.
        /// </summary>
        /// <param name="element">The XML element instance.</param>
        /// <param name="name">The name of the attribute whose value is being requested.</param>
        /// <param name="comparisonType">One of the System.StringComparison values.</param>
        /// <returns>The value of the specified attribute or null if the attribute doesn't exist.</returns>
        public static String AttributeValue(this XElement element, XName name, StringComparison comparisonType)
        {
            foreach (XAttribute attr in element.Attributes())
            {
                if (String.Compare(attr.Name.LocalName, name.LocalName, comparisonType) == 0)
                {
                    return attr.Value;
                }
            }

            return null;
        }

        /// <summary>
        /// This method returns the first value of the attribute matching the specified name.
        /// </summary>
        /// <remarks>TODO: unused</remarks>
        /// <param name="element">The XML element instance.</param>
        /// <param name="name">The name of the attribute whose value is being requested.</param>
        /// <returns>The value of the specified attribute or null if the attribute doesn't exist.</returns>
        public static String AttributeValue(this XElement element, XName name)
        {
            return element.AttributeValue(name, StringComparison.CurrentCulture);
        }
    }
}
