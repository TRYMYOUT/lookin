using System;
using System.Collections.Generic;
using System.Runtime.Serialization;
using System.Text;

namespace CasabaSecurity.Web.Watcher
{
    /// <summary>
    /// This is the base Watcher exception type.
    /// </summary>
    public class WatcherException : Exception, ISerializable
    {
        public WatcherException() : base()
        {
        }

        public WatcherException(string message)
            : base(message)
        {
        }

        public WatcherException(string message, Exception inner)
            : base(message, inner)
        {
        }

        // This constructor is needed for serialization.
        protected WatcherException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
