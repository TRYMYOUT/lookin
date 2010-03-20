﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Runtime.Remoting.Messaging;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using System.Runtime.InteropServices;
using System.IO;

//Code sample taken from www.doogal.co.uk

namespace WatcherEngine
{

    /// <summary>
    /// Class to log exceptions
    /// </summary>
    public static class ExceptionLogger
    {
        private static string filename;
        private static Object objLock = new Object();

        public static void HandleException(Exception e)
        {
            lock (objLock)
            {
                Assembly execAssembly;
                string pathlocation;
                int index;
                //Get Where we are executing
                execAssembly = Assembly.GetExecutingAssembly();
                pathlocation = execAssembly.Location;

                //Remove the filename to get the path
                index = pathlocation.LastIndexOf('\\');
                filename = pathlocation.Substring(0, index) + "\\watcher_exceptions.txt";

                List<string> data = new List<string>();

                lock (filename)
                {
                    if (File.Exists(filename))
                    {
                        using (StreamReader reader = new StreamReader(filename))
                        {
                            string line = null;
                            do
                            {
                                line = reader.ReadLine();
                                data.Add(line);
                            }
                            while (line != null);
                        }
                    }

                    // truncate the file if it's too long
                    int writeStart = 0;
                    if (data.Count > 5000)
                        writeStart = data.Count - 5000;

                    using (StreamWriter stream = new StreamWriter(filename, false))
                    {
                        for (int i = writeStart; i < data.Count; i++)
                        {
                            stream.WriteLine(data[i]);
                        }

                        stream.Write(LogException(e));
                    }
                }
            }
        }

        // Event handler that will be called when an unhandled
        // exception is caught
        public static void OnThreadException(object sender, ThreadExceptionEventArgs e)
        {
            // Log the exception to a file
            HandleException(e.Exception);
        }

        public static void OnUnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            HandleException((Exception)e.ExceptionObject);
        }

        private static string GetExceptionTypeStack(Exception e)
        {
            if (e.InnerException != null)
            {
                StringBuilder message = new StringBuilder();
                message.AppendLine(GetExceptionTypeStack(e.InnerException));
                return (message.ToString());
            }
            else
            {
                return ("   " + e.GetType().ToString());
            }
        }

        private static string GetExceptionMessageStack(Exception e)
        {
            if (e.InnerException != null)
            {
                StringBuilder message = new StringBuilder();
                message.AppendLine(GetExceptionMessageStack(e.InnerException));
                return (message.ToString());
            }
            else
            {
                return ("   " + e.Message);
            }
        }

        private static string GetExceptionCallStack(Exception e)
        {
            if (e.InnerException != null)
            {
                StringBuilder message = new StringBuilder();
                message.AppendLine(GetExceptionCallStack(e.InnerException));
                message.AppendLine("--- Next Call Stack:");
                return (message.ToString());
            }
            else
            {
                return (e.StackTrace);
            }
        }

        private static TimeSpan GetSystemUpTime()
        {
            PerformanceCounter upTime = new PerformanceCounter("System", "System Up Time");
            upTime.NextValue();
            return TimeSpan.FromSeconds(upTime.NextValue());
        }

        // use to get memory available
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private class MEMORYSTATUSEX
        {
            public uint dwLength;
            public uint dwMemoryLoad;
            public ulong ullTotalPhys;
            public ulong ullAvailPhys;
            public ulong ullTotalPageFile;
            public ulong ullAvailPageFile;
            public ulong ullTotalVirtual;
            public ulong ullAvailVirtual;
            public ulong ullAvailExtendedVirtual;

            public MEMORYSTATUSEX()
            {
                this.dwLength = (uint)Marshal.SizeOf(typeof(MEMORYSTATUSEX));
            }
        }

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool GlobalMemoryStatusEx([In, Out] MEMORYSTATUSEX lpBuffer);

        /// 
        /// writes exception details to the registered loggers
        /// 
        private static string LogException(Exception exception)
        {
            DateTime now = System.DateTime.Now;
            StringBuilder error = new StringBuilder();

            error.AppendLine("Application:       " + Application.ProductName);
            error.AppendLine("Version:           " + Application.ProductVersion);
            error.AppendLine("Date:              " + DateTime.Now.ToString("dd/MM/yyyy HH:mm:ss"));
            error.AppendLine("Computer name:     " + SystemInformation.ComputerName);
            error.AppendLine("User name:         " + SystemInformation.UserName);
            error.AppendLine("OS:                " + Environment.OSVersion.ToString());
            error.AppendLine("Culture:           " + CultureInfo.CurrentCulture.Name);
            error.AppendLine("Resolution:        " + SystemInformation.PrimaryMonitorSize.ToString());
            error.AppendLine("System up time:    " + GetSystemUpTime());
            error.AppendLine("App up time:       " +
              (DateTime.Now - Process.GetCurrentProcess().StartTime).ToString());

            MEMORYSTATUSEX memStatus = new MEMORYSTATUSEX();
            if (GlobalMemoryStatusEx(memStatus))
            {
                error.AppendLine("Total memory:      " + memStatus.ullTotalPhys / (1024 * 1024) + "Mb");
                error.AppendLine("Available memory:  " + memStatus.ullAvailPhys / (1024 * 1024) + "Mb");
            }

            error.AppendLine("");

            error.AppendLine("Exception classes:   ");
            error.Append(GetExceptionTypeStack(exception));
            error.AppendLine("");
            error.AppendLine("Exception messages: ");
            error.Append(GetExceptionMessageStack(exception));

            error.AppendLine("");
            error.AppendLine("Stack Traces:");
            error.Append(GetExceptionCallStack(exception));
            error.AppendLine("");
            error.AppendLine("Loaded Modules:");
            Process thisProcess = Process.GetCurrentProcess();
            foreach (ProcessModule module in thisProcess.Modules)
            {
                error.AppendLine(module.FileName + " " + module.FileVersionInfo.FileVersion);
            }

            return error.ToString();
        }
    }
}