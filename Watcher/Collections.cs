// WATCHER
//
// Collections.cs
// Implements the Watcher collections.
//
// Copyright (c) 2009 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security;
using System.Text;
using Fiddler;

namespace CasabaSecurity.Web.Watcher.Collections
{
    #region FiddlerSessionCollection

    /// <summary>
    /// A thread-safe collection of tracked Fiddler Sessions.
    /// </summary>
    /// <remarks>
    /// 1. This class hides the "public" use of a List<>, per the Framework Guidelines (and for synchronization purposes)
    /// 2. By default, this type instantiates a list of size MaximumSessionElements.
    /// </remarks>
    public sealed class FiddlerSessionCollection
    {
        #region Fields
        private const int MaximumSessionElements = 200;     // Maximum number of sessions to keep track of
        private const int SessionListAdjustmentSize = 10;   // Number of elements to remove from the session list when the maximum has been reached
        private Object _lock = new Object();                // Use this object to provide synchronization
        private List<Fiddler.Session> _list;                // Aggregate the List type to provide synchronized access
        #endregion

        #region Ctor(s)
        public FiddlerSessionCollection()
        {
            _list = new List<Fiddler.Session>(MaximumSessionElements);
        }
        #endregion

        #region Public Method(s)

        /// <summary>
        /// Adds the specified Fiddler session to the end of the collection in a thread-safe fashion.
        /// </summary>
        /// <param name="session">The session to add to the collection.</param>
        public void Add(Fiddler.Session session)
        {
            lock (_lock)
            {
                // Create some room in the session list if the maximum size has been reached.
                if (_list.Count == MaximumSessionElements)
                {
                    Trace.TraceInformation("Maximum session element threshold reached ({0}); removing {1} oldest elements.", MaximumSessionElements, SessionListAdjustmentSize);
                    _list.RemoveRange(0, SessionListAdjustmentSize);
                }

                // Add specified session to the running session list.
                _list.Add(session);
            }
        }

        /// <summary>
        /// Searches for an element that matches the conditions defined by the specified predicate, and returns the first occurrence within the entire collection.
        /// </summary>
        /// <param name="match">A predicate determining the match criteria for the search.</param>
        /// <returns>The first element that matches if found; otherwise the default value for the type (null).</returns>
        public Fiddler.Session Find(Predicate<Fiddler.Session> match)
        {
            lock (_lock)
            {
                return _list.Find(match);
            }
        }

        #endregion
    }

    #endregion

    #region TrustedDomainCollection

    /// <summary>
    /// A collection of Trusted Domain names.
    /// </summary>
    /// <remarks>
    /// This class hides the "public" use of a List<>, per the Framework Guidelines.
    /// </remarks>
    public sealed class TrustedDomainCollection : List<String>
    {
        public TrustedDomainCollection()
        {
        }

        public TrustedDomainCollection(int capacity)
            : base(capacity)
        {
        }

        public TrustedDomainCollection(IEnumerable<String> collection)
            : base(collection)
        {
        }
    }

    #endregion

    #region WatcherCheckCollection
    public sealed class WatcherCheckCollection : List<WatcherCheck>
    {
        #region Ctor(s)

        public WatcherCheckCollection()
            : base()
        {
        }

        public WatcherCheckCollection(int capacity)
            : base(capacity)
        {
        }

        public WatcherCheckCollection(IEnumerable<WatcherCheck> collection)
            : base(collection)
        {
        }

        #endregion

        #region Public Method(s)

        /// <summary>
        /// This method retrieves a list of Watcher add-in checks.
        /// </summary>
        /// <returns>The list of available checks.</returns>
        public void Load()
        {
            try
            {
                Trace.TraceInformation("Populating the list of available checks.");

                // Path where the application was spawned
                String currentDirectory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
                Trace.TraceInformation("Using directory {0}.", currentDirectory);

                // Examine the DLLs in the application directory, and add valid checks contained
                // in the assemblies to the list of available checks.
                String[] availableAssemblies = Directory.GetFiles(currentDirectory, "*.dll");
                foreach (String file in availableAssemblies)
                {
                    Trace.TraceInformation("Examining file {0}.", file);
                    LoadChecksFromAssembly(file);
                }

                // Enable previously unknown checks or, Enable/Disable known checks based on the
                // check's settings in the application configuration.
                EnableDisableChecks();

                Trace.TraceInformation("Found {0} checks.", this.Count);
            }

            catch (ArgumentException e)
            {
                // Thrown if there are invalid parameters to one of the methods
                Trace.TraceError("Error: ArgumentException: {0}", e.Message);
            }

            catch (PathTooLongException e)
            {
                // Thrown if the path exceeds the system defined maximum
                Trace.TraceError("Error: PathTooLongException: {0}", e.Message);
            }

            catch (UnauthorizedAccessException e)
            {
                // Thrown if there is an operating system error
                Trace.TraceError("Error: UnauthorizedAccessException: {0}", e.Message);
            }

            catch (DirectoryNotFoundException e)
            {
                // Thrown when the path cannot be found
                Trace.TraceError("Error: DirectoryNotFoundException: {0}", e.Message);
            }
        }

        #endregion

        #region Private Method(s)

        /// <summary>
        /// Examine the specified file for Watcher checks and add them to the list of available checks.
        /// </summary>
        /// <remarks>If one error occurs, skip the entire assembly.</remarks>
        /// <param name="file">Assembly to examine for checks.</param>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2001:AvoidCallingProblematicMethods", MessageId = "System.Reflection.Assembly.LoadFrom")]
        private void LoadChecksFromAssembly(String file)
        {
            try
            {
                // Load the assembly into the current application domain and search for Watcher checks
                // TODO: Load checks in separate AppDomain
                Assembly assembly = Assembly.LoadFrom(file);
                foreach (Type type in assembly.GetExportedTypes())
                {
                    if (type.IsSubclassOf(typeof(WatcherCheck)))
                    {
                        // Instantiate and store the type instance if derived from the WatcherCheck
                        WatcherCheck checkInstance = (WatcherCheck)Activator.CreateInstance(type);
                        this.Add(checkInstance);

                        Trace.TraceInformation("Found Watcher check \"{0}\"", checkInstance.GetName());
                    }
                }
            }

            catch (ArgumentException e)
            {
                // Thrown if there are invalid parameters to one of the methods
                Trace.TraceError("Error: ArgumentException: {0}", e.Message);
            }

            catch (PathTooLongException e)
            {
                // Thrown if the path exceeds the system defined maximum
                Trace.TraceError("Error: PathTooLongException: {0}", e.Message);
            }

            catch (FileNotFoundException e)
            {
                // Thrown when the file does not exist
                Trace.TraceError("Error: FileNotFoundException: {0}", e.Message);
            }

            catch (FileLoadException e)
            {
                // Thrown when the assembly is found but cannot be loaded
                Trace.TraceError("Error: FileLoadException: {0}", e.Message);
            }

            catch (BadImageFormatException e)
            {
                // Thrown when the file image is invalid
                Trace.TraceError("Error: BadImageFormatException: {0}", e.Message);
            }

            catch (SecurityException e)
            {
                // Thrown when a security error is detected
                Trace.TraceError("Error: SecurityException: {0}", e.Message);
            }

            catch (TargetInvocationException e)
            {
                // Thrown by the constructor of the instantiated type
                Trace.TraceError("Error: TargetInvocationException: {0}", e.Message);
            }

            catch (MethodAccessException e)
            {
                // Thrown when the instance constructor cannot be invoked
                Trace.TraceError("Error: MethodAccessException: {0}", e.Message);
            }

            catch (TypeLoadException e)
            {
                // Thrown when a type load error occurs
                Trace.TraceError("Error: TypeLoadException: {0}", e.Message);
            }
        }

        /// <summary>
        /// Enable/Disable each known checks based on the check's settings in the application configuration,
        /// otherwise use the check's default setting (via WatcherCheck.Enabled).
        /// </summary>
        private void EnableDisableChecks()
        {
            Trace.TraceInformation("Setting check enabled/disabled flags (based on the application configuration).");

            // Enumerate the checks and enable/disable them according to the configuration
            foreach (WatcherCheck check in this)
            {
                check.Enabled = WatcherEngine.Configuration.GetCheckEnabledConfig(check);
            }
        }

        #endregion
    }
    #endregion
}
