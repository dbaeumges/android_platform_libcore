/*
 * Copyright (c) 2010 The Pennsylvania State University
 * Systems and Internet Infrastructure Security Laboratory
 *
 * Author: William Enck <enck@cse.psu.edu>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package dalvik.system;

import java.io.FileDescriptor;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.text.SimpleDateFormat;
import org.json.JSONException;
import org.json.JSONStringer;

/**
 * Provides a Taint interface for the Dalvik VM. This class is used for
 * implementing Taint Source and Sink functionality.
 * 
 */
public final class Taint {

    public static final int TAINT_CLEAR		= 0x00000000;
    public static final int TAINT_LOCATION	= 0x00000001;
    public static final int TAINT_CONTACTS	= 0x00000002;
    public static final int TAINT_MIC           = 0x00000004;
    public static final int TAINT_PHONE_NUMBER  = 0x00000008;
    public static final int TAINT_LOCATION_GPS  = 0x00000010;
    public static final int TAINT_LOCATION_NET  = 0x00000020;
    public static final int TAINT_LOCATION_LAST = 0x00000040;
    public static final int TAINT_CAMERA        = 0x00000080;
    public static final int TAINT_ACCELEROMETER = 0x00000100;
    public static final int TAINT_SMS           = 0x00000200;
    public static final int TAINT_IMEI          = 0x00000400;
    public static final int TAINT_IMSI          = 0x00000800;
    public static final int TAINT_ICCID         = 0x00001000;
    public static final int TAINT_DEVICE_SN     = 0x00002000;
    public static final int TAINT_ACCOUNT       = 0x00004000;
    public static final int TAINT_HISTORY       = 0x00008000;
    public static final int TAINT_INCOMING_DATA = 0x00010000;
    public static final int TAINT_USER_INPUT    = 0x00020000;

    /**
     * Updates the target String's taint tag.
     *
     * @param str
     *	    the target string
     * @param tag
     *	    tag to update (bitwise or) onto the object
     */
    native public static void addTaintString(String str, int tag);

    /**
     * Updates the target CharSequence's taint tag.
     *
     * @param cs
     *	    the target CharSequence
     * @param tag
     *	    tag to update (bitwise or) onto the object
     */
    native public static void addTaintCharSequence(CharSequence cs, int tag);
    
    /**
     * Updates the target Object array's taint tag.
     *
     * @param array
     *	    the target object array
     * @param tag
     *	    tag to update (bitwise or) onto the object array
     */
    native public static void addTaintObjectArray(Object[] array, int tag);

    /**
     * Updates the target boolean array's taint tag.
     *
     * @param array
     *	    the target boolean array
     * @param tag
     *	    tag to update (bitwise or) onto the boolean array
     */
    native public static void addTaintBooleanArray(boolean[] array, int tag);

    /**
     * Updates the target char array's taint tag.
     *
     * @param array
     *	    the target char array
     * @param tag
     *	    tag to update (bitwise or) onto the char array
     */
    native public static void addTaintCharArray(char[] array, int tag);

    /**
     * Updates the target byte array's taint tag.
     *
     * @param array
     *	    the target byte array
     * @param tag
     *	    tag to update (bitwise or) onto the byte array
     */
    native public static void addTaintByteArray(byte[] array, int tag);

    /**
     * Updates the target int array's taint tag.
     *
     * @param array
     *	    the target int array
     * @param tag
     *	    tag to update (bitwise or) onto the int array
     */
    native public static void addTaintIntArray(int[] array, int tag);
    
    /**
     * Updates the target short array's taint tag.
     *
     * @param array
     *	    the target short array
     * @param tag
     *	    tag to update (bitwise or) onto the int array
     */
    native public static void addTaintShortArray(short[] array, int tag);

    /**
     * Updates the target long array's taint tag.
     *
     * @param array
     *	    the target long array
     * @param tag
     *	    tag to update (bitwise or) onto the long array
     */
    native public static void addTaintLongArray(long[] array, int tag);

    /**
     * Updates the target float array's taint tag.
     *
     * @param array
     *	    the target float array
     * @param tag
     *	    tag to update (bitwise or) onto the float array
     */
    native public static void addTaintFloatArray(float[] array, int tag);

    /**
     * Updates the target double array's taint tag.
     *
     * @param array
     *	    the target double array
     * @param tag
     *	    tag to update (bitwise or) onto the double array
     */
    native public static void addTaintDoubleArray(double[] array, int tag);
    
    /**
     * Add taint to a primiative boolean value. Only the return value has the
     * updated taint tag.
     *
     * @param val
     *	    the input value
     * @param tag
     *	    tag to add (bitwise or) onto the input value
     * @return val with the added taint tag
     */
    native public static boolean addTaintBoolean(boolean val, int tag);
    
    /**
     * Add taint to a primiative char value. Only the return value has the
     * updated taint tag.
     *
     * @param val
     *	    the input value
     * @param tag
     *	    tag to add (bitwise or) onto the input value
     * @return val with the added taint tag
     */
    native public static char addTaintChar(char val, int tag);
    
    /**
     * Add taint to a primiative byte value. Only the return value has the
     * updated taint tag.
     *
     * @param val
     *	    the input value
     * @param tag
     *	    tag to add (bitwise or) onto the input value
     * @return val with the added taint tag
     */
    native public static byte addTaintByte(byte val, int tag);

    /**
     * Add taint to a primiative int value. Only the return value has the
     * updated taint tag.
     *
     * @param val
     *	    the input value
     * @param tag
     *	    tag to add (bitwise or) onto the input value
     * @return val with the added taint tag
     */
    native public static int addTaintInt(int val, int tag);

    /**
     * Add taint to a primiative long value. Only the return value has the
     * updated taint tag.
     *
     * @param val
     *	    the input value
     * @param tag
     *	    tag to add (bitwise or) onto the input value
     * @return val with the added taint tag
     */
    native public static long addTaintLong(long val, int tag);

    /**
     * Add taint to a primiative float value. Only the return value has the
     * updated taint tag.
     *
     * @param val
     *	    the input value
     * @param tag
     *	    tag to add (bitwise or) onto the input value
     * @return val with the added taint tag
     */
    native public static float addTaintFloat(float val, int tag);

    /**
     * Add taint to a primiative double value. Only the return value has the
     * updated taint tag.
     *
     * @param val
     *	    the input value
     * @param tag
     *	    tag to add (bitwise or) onto the input value
     * @return val with the added taint tag
     */
    native public static double addTaintDouble(double val, int tag);

    /**
     * Get the current taint tag from a String.
     *
     * @param str
     *	    the target String
     * @return the taint tag
     */
    native public static int getTaintString(String str);

    /**
     * Get the current taint tag from a CharSequence.
     *
     * @param cs
     *	    the target CharSequence
     * @return the taint tag
     */
    native public static int getTaintCharSequence(CharSequence cs);

    /**
     * Get the current taint tag from an Object array.
     *
     * @param array 
     *	    the target Object array
     * @return the taint tag
     */
    native public static int getTaintObjectArray(Object[] array);

    /**
     * Get the current taint tag from a boolean array.
     *
     * @param array 
     *	    the target boolean array
     * @return the taint tag
     */
    native public static int getTaintBooleanArray(boolean[] array);

    /**
     * Get the current taint tag from a char array.
     *
     * @param array 
     *	    the target char array
     * @return the taint tag
     */
    native public static int getTaintCharArray(char[] array);

    /**
     * Get the current taint tag from a byte array.
     *
     * @param array 
     *	    the target byte array
     * @return the taint tag
     */
    native public static int getTaintByteArray(byte[] array);

    /**
     * Get the current taint tag from an int array.
     *
     * @param array 
     *	    the target int array
     * @return the taint tag
     */
    native public static int getTaintIntArray(int[] array);

    /**
     * Get the current taint tag from a short array.
     *
     * @param array 
     *	    the target short array
     * @return the taint tag
     */
    native public static int getTaintShortArray(short[] array);

    /**
     * Get the current taint tag from a long array.
     *
     * @param array 
     *	    the target long array
     * @return the taint tag
     */
    native public static int getTaintLongArray(long[] array);

    /**
     * Get the current taint tag from a float array.
     *
     * @param array 
     *	    the target float array
     * @return the taint tag
     */
    native public static int getTaintFloatArray(float[] array);

    /**
     * Get the current taint tag from a double array.
     *
     * @param array 
     *	    the target double array
     * @return the taint tag
     */
    native public static int getTaintDoubleArray(double[] array);

    /**
     * Get the current taint tag from a primiative boolean.
     *
     * @param val
     *	    the target boolean
     * @return the taint tag
     */
    native public static int getTaintBoolean(boolean val);

    /**
     * Get the current taint tag from a primiative char.
     *
     * @param val
     *	    the target char 
     * @return the taint tag
     */
    native public static int getTaintChar(char val);

    /**
     * Get the current taint tag from a primiative byte.
     *
     * @param val
     *	    the target byte 
     * @return the taint tag
     */
    native public static int getTaintByte(byte val);

    /**
     * Get the current taint tag from a primiative int.
     *
     * @param val
     *	    the target int 
     * @return the taint tag
     */
    native public static int getTaintInt(int val);

    /**
     * Get the current taint tag from a primiative long.
     *
     * @param val
     *	    the target long 
     * @return the taint tag
     */
    native public static int getTaintLong(long val);

    /**
     * Get the current taint tag from a primiative float.
     *
     * @param val
     *	    the target float 
     * @return the taint tag
     */
    native public static int getTaintFloat(float val);

    /**
     * Get the current taint tag from a primiative double.
     *
     * @param val
     *	    the target double 
     * @return the taint tag
     */
    native public static int getTaintDouble(double val);

    /**
     * Get the current taint tag from an Object reference.
     *
     * @param obj
     *	    the target Object reference
     * @return the taint tag
     */
    native public static int getTaintRef(Object obj);
    
    /**
     * Get the taint tag from a file identified by a descriptor.
     *
     * @param fd
     *	    the target file descriptor
     * @return the taint tag
     */
    native public static int getTaintFile(int fd);
    
    /**
     * add a taint tag to a file identified by a descriptor
     *
     * @param fd
     *	    the target file descriptor
     * @param tag
     *	    the tag to add (bitwise or) to the file
     */
    native public static void addTaintFile(int fd, int tag);

    /**
     * Logging utility accessible from places android.util.Log
     * is not.
     *
     * @param msg
     *	    the message to log
     */
    native public static void log(String msg);


    /**
     * Logging utiltity to obtain the file path for a file descriptor
     *
     * @param fd
     *	    the file descriptor
     */
    native public static void logPathFromFd(int fd);

    /**
     * Logging utiltity to obtain the peer IP addr for a file descriptor
     *
     * @param fd
     *	    the file descriptor
     */
    native public static void logPeerFromFd(int fd);

    
    /**
     * Logging utility to log cipher usage within android.
     *
     * @param theAction
     *	    the cipher action: init, update, or doFinal
     * @param theId
     *      unique id for the cipher action
     * @param theMode
     *      decryption (2) or encryption (1)
     * @param theInput
     *      input byte stream
     * @param theOutput
     *      output byte stream
     */
    public static void logCipherUsage(String theAction, int theId, int theMode, byte[] theInput, byte[] theOutput)
    {
        String aLogStr = "";
        int aTag = Taint.getTaintByteArray(theInput);
        String aTagStr = "0x" + Integer.toHexString(aTag);
        String aInputStr = "";
        if (theInput != null)
        {
            aInputStr = new String(theInput);
        }
        String aOutputStr = "";
        if (theOutput != null)
        {
            aOutputStr = new String(theOutput);
        }
        String aStackTraceStr = "";
        String aTimestamp = "";
        if (theAction == "init")
        {
            aStackTraceStr = getStackTrace();
            aTimestamp = getTimestamp();
        }
        try
        {
            aLogStr = new JSONStringer()
              .array()
                .object()
                  .key("__CipherUsageLogEntry__")
                  .value("true")
                  .key("action")
                  .value(theAction)
                  .key("id")
                  .value(theId)
                  .key("mode")
                  .value(theMode)
                  .key("tag")
                  .value(aTagStr)
                  .key("input")
                  .value(aInputStr)
                  .key("output")
                  .value(aOutputStr)
                  .key("stackTraceStr")
                  .value(aStackTraceStr)
                  .key("timestamp")
                  .value(aTimestamp)
                .endObject()
              .endArray()
            .toString();
        } 
        catch (JSONException ex) 
        {            
            log("JSON Exception thrown: " + ex.toString());
            String aIdStr = Integer.toString(theId);
            String aModeStr = Integer.toString(theMode);
            aLogStr = "[{\"__CipherUsageLogEntry__\" : \"true"
                + "\", \"action\" : \"" + theAction
                + "\", \"id\": \"" + aIdStr
                + "\", \"mode\": \"" + aModeStr
                + "\", \"tag\": \"" + aTagStr 
                + "\", \"input\": \"" + escapeJson(aInputStr)
                + "\", \"output\": \"" + escapeJson(aOutputStr)
                + "\", \"stackTraceStr\": \"" + escapeJson(aStackTraceStr) 
                + "\", \"timestamp\": \"" + aTimestamp + "\"}]";
        }
        log(aLogStr);
    }

    /**
     * Logging utiltity for OS file system actions
     *
     * @param theAction
     *	    file system action, e.g. read or write
     * @param theTag
     *      taint tag value
     * @param theFileDescriptor
     *      file descriptor id
     * @param theData
     *      data written or read
     */
    public static void logFileSystem(String theAction, int theTag, int theFileDescriptor, String theData)
    {
        String aFileDescriptorStr = Integer.toString(theFileDescriptor);
        Taint.logPathFromFd(theFileDescriptor); // Log file descriptor first
        
        String aLogStr = "";
        String aTagStr = "0x" + Integer.toHexString(theTag);
        String aStackTraceStr = getStackTrace();
        String aTimestamp = ""; //getTimestamp();

        try
        {
            aLogStr = new JSONStringer()
              .array()
                .object()
                  .key("__FileSystemLogEntry__")
                  .value("true")
                  .key("action")
                  .value(theAction)
                  .key("tag")
                  .value(aTagStr)
                  .key("fileDescriptor")
                  .value(theFileDescriptor)
                  .key("data")
                  .value(theData)
                  .key("stackTraceStr")
                  .value(aStackTraceStr)
                  .key("timestamp")
                  .value(aTimestamp)
                .endObject()
              .endArray()
            .toString();
        } 
        catch (JSONException ex) 
        {
            log("JSON Exception thrown: " + ex.toString());
            String aFileDescriptorString = Integer.toString(theFileDescriptor);
            aLogStr = "[{\"__FileSystemLogEntry__\" : \"true"
                + "\", \"action\" : \"" + theAction
                + "\", \"tag\": \"" + aTagStr 
                + "\", \"fileDescriptor\": \"" + aFileDescriptorString
                + "\", \"data\": \""+ escapeJson(theData) 
                + "\", \"stackTraceStr\": \"" + escapeJson(aStackTraceStr)
                + "\", \"timestamp\": \"" + aTimestamp + "\"}]";
        }

        log(aLogStr);
    }

    /**
     * Logging utiltity for OS network actions
     *
     * @param theAction
     *	    network action, e.g. send or recv
     * @param theTag
     *      taint tag value
     * @param theDestination
     *      destination address
     * @param thePort
     *      destination port
     * @param theData
     *      data send or received
     */
    public static void logNetworkAction(String theAction, int theTag, String theDestination, int thePort, String theData)
    {
        String aLogStr = "";
        String aTagStr = "0x" + Integer.toHexString(theTag);
        String aStackTraceStr = getStackTrace();
        String aTimestamp = getTimestamp();

        try
        {
            aLogStr = new JSONStringer()
              .array()
                .object()
                  .key("__NetworkSendLogEntry__")
                  .value("true")
                  .key("action")
                  .value(theAction)
                  .key("tag")
                  .value(aTagStr)
                  .key("destination")
                  .value(theDestination)
                  .key("port")
                  .value(thePort)
                  .key("data")
                  .value(theData)
                  .key("stackTraceStr")
                  .value(aStackTraceStr)
                  .key("timestamp")
                  .value(aTimestamp)
                .endObject()
              .endArray()
            .toString();
        } 
        catch (JSONException ex) 
        {            
            log("JSON Exception thrown: " + ex.toString());
            String aPortStr = Integer.toString(thePort);
            aLogStr = "[{\"__NetworkSendLogEntry__\" : \"true"
                + "\", \"action\" : \"" + theAction
                + "\", \"tag\": \"" + aTagStr 
                + "\", \"destination\": \"" + theDestination 
                + "\", \"port\": \"" + aPortStr 
                + "\", \"data\": \"" + escapeJson(theData)
                + "\", \"stackTraceStr\": \"" + escapeJson(aStackTraceStr)
                + "\", \"timestamp\": \"" + aTimestamp + "\"}]";
        }
        log(aLogStr);
    }

    /**
     * Logging utiltity for SMS actions
     *
     * @param theAction
     *	    SMS action, e.g. sendSms or sendDataMessage
     * @param theDestination
     *      destination phone number
     * @param theText
     *      text to be sent
     */
    public static void logSmsAction(String theAction, String theDestination, String theScAddress, String theText)
    {
        String aLogStr = "";
        int aTag = Taint.getTaintString(theText);
        String aTagStr = "0x" + Integer.toHexString(aTag);
        String aStackTraceStr = getStackTrace();
        String aTimestamp = getTimestamp();

        try
        {
            aLogStr = new JSONStringer()
              .array()
                .object()
                  .key("__SendSmsLogEntry__")
                  .value("true")
                  .key("action")
                  .value(theAction)
                  .key("tag")
                  .value(aTagStr)
                  .key("destination")
                  .value(theDestination)
                  .key("scAddress")
                  .value(theScAddress)
                  .key("text")
                  .value(theText)
                  .key("stackTraceStr")
                  .value(aStackTraceStr)
                  .key("timestamp")
                  .value(aTimestamp)
                .endObject()
              .endArray()
            .toString();
        } 
        catch (JSONException ex) 
        {            
            log("JSON Exception thrown: " + ex.toString());
            aLogStr = "[{\"__SendSmsLogEntry__\" : \"true"
                + "\", \"action\" : \"" + theAction
                + "\", \"tag\": \"" + aTagStr 
                + "\", \"destination\": \"" + theDestination 
                + "\", \"scAddress\": \"" + theScAddress
                + "\", \"text\": \"" + escapeJson(theText)
                + "\", \"stackTraceStr\": \"" + escapeJson(aStackTraceStr)
                + "\", \"timestamp\": \"" + aTimestamp + "\"}]";
        }
        log(aLogStr);
    }

    /**
     * Logging utiltity for sending multipart SMS
     *
     * @param theDestination
     *      destination phone number
     * @param theTextParts
     *      text parts to be sent
     */
    public static void logSendMultipartSms(String theDestination, String theScAddress, ArrayList<String> theTextParts)
    {
        String aText = "";
        for (String aTextPart : theTextParts)
        {
            aText += aTextPart;
        }
        logSmsAction("sendMultipartSms", theDestination, theScAddress, aText);
    }

    /**
     * Logging utiltity for sending data SMS
     *
     * @param theDestination
     *      destination phone number
     * @param thePort
     *      destination phone port
     * @param theData
     *      data to be sent
     */
    public static void logSendDataMessage(String theDestination, String theScAddress, int thePort, byte[] theData)
    {
        String aPortStr = Integer.toString(thePort);
        String aDestination = theDestination + ":" + aPortStr;
        String aText = new String(theData);
        logSmsAction("sendDataMessage", aDestination, theScAddress, aText);
    }
    
    private static String getStackTrace()
    {
        String aStackTraceStr = "";
        StackTraceElement[] aStackTraceElementVec = Thread.currentThread().getStackTrace();
        for (int i = 0 ; i < aStackTraceElementVec.length; i++)
        {
            StackTraceElement aStackTraceElement = aStackTraceElementVec[i];
            String aClassname = aStackTraceElement.getClassName();
            String aMethodName = aStackTraceElement.getMethodName();
            int aLineNumber = aStackTraceElement.getLineNumber();
            aStackTraceStr += aClassname + "," + aMethodName + ":" + aLineNumber + "||";
        }

        return aStackTraceStr;
    }

    private static String getTimestamp()
    {
        SimpleDateFormat aDateFormat = new SimpleDateFormat("yyyyMMddHHmmss");
        return aDateFormat.format(new Date(System.currentTimeMillis()));
    }

    private static String escapeJson(String theString)
    {
        if (theString == null)
        {
            return null;
        }
        StringBuffer aStringBuf = new StringBuffer();

        for (int i = 0; i < theString.length(); i++)
        {
            char aChar = theString.charAt(i);
            switch(aChar)
            {
            case '"':
            case '\\':
            case '/':
                aStringBuf.append("\\").append(aChar);
                break;
            case '\b':
                aStringBuf.append("\\b");
                break;
            case '\f':
                aStringBuf.append("\\f");
                break;
            case '\n':
                aStringBuf.append("\\n");
                break;
            case '\r':
                aStringBuf.append("\\r");
                break;
            case '\t':
                aStringBuf.append("\\t");
                break;
            default:
                if (aChar >= 0x00 && aChar <= 0x1F)
                {
                    aStringBuf.append(String.format("\\u%04x", (int)aChar));
                }
                else
                {
                    aStringBuf.append(aChar);
                }
                break;
            }
        }

        return aStringBuf.toString(); 
    }
}

