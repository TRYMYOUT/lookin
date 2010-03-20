// WATCHER
//
// Check.Pasv.Unicode.InvalidUTF8.cs
// Checks for illformed UTF-8 byte sequences in content.
//
// Copyright (c) 2010 Casaba Security, LLC
// All Rights Reserved.
//

using System;
using System.Text;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.IO;
using Fiddler;

namespace CasabaSecurity.Web.Watcher.Checks
{
    public struct checkreturn
    {
        public int size;
        public int goal;
        public bool validity;

        public checkreturn(int i, int g, bool v)
        {
            size = i;
            goal = g;
            validity = v;
        }
    }

    /// <summary>
    /// Look for invalid UTF-8 ByteStreams
    /// Currently checks all streams no matter the charset reported.
    /// 
    /// TODO: Consider adding support for specifically reporting overlong UTF-8 
    /// </summary>
    public class CheckPasvUnicodeInvalidUTF8 : WatcherCheck
    {
        #region Fields
        [ThreadStatic] static private string alertbody = "";
        [ThreadStatic] static private string alertbody2 = "";
        [ThreadStatic] static private int findingnum;
        [ThreadStatic] static private int findingnum2;
        #endregion

        public override String GetName()
        {
            return "Unicode - Identify ill-formed Unicode UTF-8 content, and null bytes in HTML.";
        }

        public override String GetDescription()
        {
            String desc = "This check reviews the byte stream of an UTF-8 encoded HTML page, and identifies " +
                    "ill-formed byte sequences as well as null bytes.  For more information see: \r\n\r\n" +
                    "http://www.lookout.net/2009/03/25/detecting-ill-formed-utf-8-byte-sequences-in-html-content/";

            return desc;
        }

        private void AddAlert(Session session)
        {
            string name = "Ill-formed UTF-8 bytes";
            string text =

                "An invalid UTF-8 ByteStream was detected for request:\r\n\r\n" +
                session.fullUrl +
                "\r\n\r\n" +
                "The following issue(s) were identified:" +
                "\r\n\r\n" +
                alertbody;

            WatcherEngine.Results.Add(WatcherResultSeverity.High, session.id, session.fullUrl, name, text, StandardsCompliance, findingnum);
        }

        private void AddAlert2(Session session)
        {
            string name = "Null bytes in content";
            string text =

                "Null Bytes in ByteStream was detected for request:\r\n\r\n" +
                session.fullUrl +
                "\r\n\r\n" +
                "The following issue(s) were identified:" +
                "\r\n\r\n" +
                alertbody2;

            WatcherEngine.Results.Add(WatcherResultSeverity.High, session.id, session.fullUrl, name, text, StandardsCompliance, findingnum2);
        }

        private void FormMessage(long position, int sequencelength, MemoryStream memstream, bool isHeader)
        {
            string message = "";
            findingnum++;
            long newposition = position + 17; //Offset for missing bytes from Fiddler
            if (isHeader)
            {
                message = message + findingnum.ToString() + ") An invalid " + sequencelength.ToString() + " character UTF-8 ByteStream was found in the header at byte position " + newposition.ToString() + "\r\n";
            }
            else
            {
                message = message + findingnum.ToString() + ") An invalid " + sequencelength.ToString() + " character UTF-8 ByteStream was found at byte position " + newposition.ToString() + "\r\n";
            }
            message = message + "Invalid byte(s): " + PrintBytes(position, sequencelength, memstream) + "\r\n";
            message = message + "and the (up to) ten bytes surrounding it are: ";
            if (position < 3) //Ensure that we do not bork if at the beginning of a stream
            {
                position = 3;
            }
            message = message + PrintBytes(position - 4, sequencelength + 10, memstream) + "\r\n\r\n";
            alertbody = alertbody + message;
        }

        private void FormMessage2(long position, MemoryStream memstream, bool isHeader)
        {
            string message = "";
            findingnum2++;
            long newposition = position + 17; //Offset for missing bytes from Fiddler
            if (isHeader)
            {
                message = message + findingnum2.ToString() + ") An Null byte in ByteStream was found in the header at byte position " + position.ToString() + "\r\n";
            }
            else
            {
                message = message + findingnum2.ToString() + ") An invalid Null byte in ByteStream was found at byte position " + newposition.ToString() + "\r\n";
            }
            message = message + "Null byte(s): " + PrintBytes(position, 1, memstream) + "\r\n";
            message = message + "and the (up to) ten bytes surrounding it are: ";
            if (position < 3) //Ensure that we do not bork if at the beginning of a stream
            {
                position = 3;
            }
            message = message + PrintBytes(position - 4, 11, memstream) + "\r\n\r\n";
            alertbody2 = alertbody2 + message;
        }

        private static string PrintBytes(long startpos, int numbytes, MemoryStream memstream)
        {
            string formattedbytes = "";
            string tempstring = "";

            int tempbyte;
            memstream.Position = startpos;
            for (long i = 0; i < numbytes; i++)
            {
                tempbyte = memstream.ReadByte();
                if (tempbyte == -1)
                {
                    formattedbytes += "<end of stream>";
                    break;
                }
                else
                {
                    tempstring = tempbyte.ToString("X").PadLeft(2, '0') + " "; //same as “%02X” in C
                }
                formattedbytes += tempstring;

            }
            return formattedbytes;
        }

        checkreturn checkByte(byte testbyte, byte secondbyte, byte thirdbyte, byte fourthbyte)
        {
            checkreturn returnvalue;
            returnvalue.validity = false;
            returnvalue.goal = 1;
            returnvalue.size = 1;

            if (testbyte == 0)
            {
                returnvalue.validity = true;
                returnvalue.size = 0;
                returnvalue.goal = 0;
                return returnvalue;
            }
            //Test for One byte Invalid Sequence
            for (byte i = 0x01; i <= 0x7F; i++)
            {
                if (testbyte == i)
                {
                    returnvalue.size = 1;
                    returnvalue.goal = 1;
                    returnvalue.validity = true;
                    return returnvalue;
                }
            }
            //Test for Two byte Invalid Sequence
            for (byte i = 0xC2; i <= 0xDF; i++)
            {
                if (testbyte == i)
                {
                    returnvalue.goal = 2;
                    returnvalue.size = 1;
                    returnvalue = testNextByte(2, 1, /*0,*/ testbyte, secondbyte, thirdbyte, fourthbyte, returnvalue);
                    return returnvalue;
                }
            }
            //Test for Three byte Invalid Sequence
            for (byte i = 0xE1; i <= 0xEF; i++)
            {
                if (testbyte == i)
                {
                    returnvalue.goal = 3;
                    returnvalue.size = 1;
                    returnvalue = testNextByte(2, 1, /*1,*/ testbyte, secondbyte, thirdbyte, fourthbyte, returnvalue);
                    return returnvalue;
                }
            }
            //Test for Four byte Invalid Sequence
            for (byte i = 0xF1; i <= 0xF3; i++)
            {
                if (testbyte == i)
                {
                    returnvalue.goal = 4;
                    returnvalue.size = 1;
                    returnvalue = testNextByte(2, 1, /*2,*/ testbyte, secondbyte, thirdbyte, fourthbyte, returnvalue);
                    return returnvalue;
                }
            }
            //Test for special case 
            if (testbyte == 0xE0)
            {
                returnvalue.goal = 3;
                returnvalue.size = 1;
                returnvalue = testNextByte(2, 2, /*1,*/ testbyte, secondbyte, thirdbyte, fourthbyte, returnvalue);
                return returnvalue;
            }

            if (testbyte == 0xF0)
            {
                returnvalue.goal = 4;
                returnvalue.size = 1;
                returnvalue = testNextByte(2, 3, /*2,*/ testbyte, secondbyte, thirdbyte, fourthbyte, returnvalue);
                return returnvalue;
            }
            if (testbyte == 0xF4)
            {
                returnvalue.goal = 4;
                returnvalue.size = 1;
                returnvalue = testNextByte(2, 4, /*2,*/ testbyte, secondbyte, thirdbyte, fourthbyte, returnvalue);
                return returnvalue;
            }
            return returnvalue;
        }

        checkreturn testNextByte(int selectedbyte, int byterange, /*int additionalchecks,*/ byte firstbyte, byte secondbyte, byte thirdbyte, byte fourthbyte, checkreturn returnvalue)
        {
            byte startrange = 0;
            byte endrange = 0;
            byte testbyte = 0;

            switch (selectedbyte)
            {
                case 1:
                    testbyte = firstbyte;
                    break;
                case 2:
                    testbyte = secondbyte;
                    break;
                case 3:
                    testbyte = thirdbyte;
                    break;
                case 4:
                    testbyte = fourthbyte;
                    break;
            }

            switch (byterange)
            {
                case 1:
                    startrange = 0x80;
                    endrange = 0xBF;
                    break;
                case 2:
                    startrange = 0xA0;
                    endrange = 0xBF;
                    break;
                case 3:
                    startrange = 0x90;
                    endrange = 0xBF;
                    break;
                case 4:
                    startrange = 0x80;
                    endrange = 0x8F;
                    break;
            }
            if (testbyte == 0)
            {
                return returnvalue;
            }
            for (byte i = startrange; i <= endrange; i++)
            {
                if (testbyte == i)
                {
                    returnvalue.size++;
                    if (returnvalue.size == returnvalue.goal)
                    {
                        returnvalue.validity = true;
                        return returnvalue;
                    }
                    else
                    {
                        return testNextByte(selectedbyte + 1, 1, firstbyte, secondbyte, thirdbyte, fourthbyte, returnvalue);
                    }
                    /*if (additionalchecks > 0)
                    {
                        additionalchecks--;
                        return testNextByte(selectedbyte + 1, 1, additionalchecks, firstbyte, secondbyte, thirdbyte, fourthbyte, returnvalue);
                    }
                    else
                    {
                        return true;
                    }*/
                }
            }
            return returnvalue;
        }

        void scanStream(MemoryStream memstream, int headersize)
        {
            byte firstbyte;
            byte secondbyte;
            byte thirdbyte;
            byte fourthbyte;
            int nextbyte;
            long sequencesize;
            long position = 0; 
            checkreturn returnvalue;

            position = memstream.Position;
            while (true)
            {
                //Set Sequence Size to 0
                sequencesize = 0;
                nextbyte = memstream.ReadByte();
                if (nextbyte == -1) // End of stream? If so, we're done
                {
                    break;
                }
                else if (nextbyte == 0)
                {
                    FormMessage2(position, memstream, position < headersize);
                }
                firstbyte = (byte)nextbyte; //First byte

                nextbyte = memstream.ReadByte();
                if (nextbyte == -1) // End of stream? If so, we're done
                {
                    secondbyte = 0;
                }
                else
                {
                    secondbyte = (byte)nextbyte; //Second Byte
                }

                nextbyte = memstream.ReadByte();
                if (nextbyte == -1) // End of stream? If so, we're done
                {
                    thirdbyte = 0;
                }
                else
                {
                    thirdbyte = (byte)nextbyte; //Third Byte
                }

                nextbyte = memstream.ReadByte();
                if (nextbyte == -1) // End of stream? If so, we're done
                {
                    fourthbyte = 0;
                }
                else
                {
                    fourthbyte = (byte)nextbyte; //Fourth Byte
                }

                //Check for byte stream and get back size of stream and sequence
                returnvalue = checkByte(firstbyte, secondbyte, thirdbyte, fourthbyte);
                sequencesize = returnvalue.size;

                //If byte stream was invalid create error message
                if (!returnvalue.validity && returnvalue.size != 0)
                {
                    FormMessage(position, returnvalue.goal, memstream, position < headersize);
                }

                //Always increment at least one byte
                if (sequencesize == 0)
                {
                    sequencesize = 1;
                }

                //Set new position
                position += sequencesize;

                //Position must be reset 
                memstream.Position = position;
            }
            //return message;

        }

        public override void Check(Session session, UtilityHtmlParser htmlparser)
        {
            MemoryStream memstreamrequest;
            alertbody = "";
            alertbody2 = "";
            findingnum = 0;
            findingnum2 = 0;

            if (WatcherEngine.Configuration.IsOriginDomain(session.hostname))
            {
                if (session.responseCode == 200)
                {
                    if (Utility.IsResponseHtml(session) || Utility.IsResponseJavascript(session) || Utility.IsResponseXml(session))
                    {
                        if (Utility.IsResponseCharset(session, "utf-8") || Utility.IsResponseCharset(session, "utf8"))
                        {
                            //First we assemble the request into a byte stream
                            Byte[] headerbytes = session.oResponse.headers.ToByteArray(false, false);
                            Byte[] bodybytes = session.responseBodyBytes;
                            Byte[] requestbytes = new byte[headerbytes.Length + bodybytes.Length + 2];
                            Buffer.BlockCopy(headerbytes, 0, requestbytes, 0, headerbytes.Length);
                            requestbytes[headerbytes.Length] = 0x0D;
                            requestbytes[headerbytes.Length + 1] = 0x0A;
                            Buffer.BlockCopy(bodybytes, 0, requestbytes, headerbytes.Length + 2, bodybytes.Length);

                            //Then we process the stream
                            memstreamrequest = new MemoryStream(requestbytes);
                            scanStream(memstreamrequest, headerbytes.Length);
                            if (!String.IsNullOrEmpty(alertbody))
                            {
                                AddAlert(session);
                            }
                            if (!String.IsNullOrEmpty(alertbody2))
                            {
                                AddAlert2(session);
                            }
                            return;
                        }
                    }
                }
            }
        }
    }
}