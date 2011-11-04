/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.apache.harmony.luni.platform;

import java.io.FileDescriptor;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.SocketImpl;
// begin WITH_TAINT_TRACKING
import dalvik.system.Taint;
// end WITH_TAINT_TRACKING

/**
 * This wraps native code that implements the INetworkSystem interface.
 * Address length was changed from long to int for performance reasons.
 */
final class OSNetworkSystem implements INetworkSystem {
    private static final OSNetworkSystem singleton = new OSNetworkSystem();

    public static OSNetworkSystem getOSNetworkSystem() {
        return singleton;
    }

    private OSNetworkSystem() {
    }

    public native void accept(FileDescriptor serverFd, SocketImpl newSocket,
            FileDescriptor clientFd) throws IOException;

    public native void bind(FileDescriptor fd, InetAddress inetAddress, int port) throws SocketException;

    // begin WITH_TAINT_TRACKING
    public void connect(FileDescriptor fd, InetAddress inetAddress, int port, int timeout) throws SocketException {
    	String addr = inetAddress.getHostAddress();
    	if (addr != null) 
        {
    	    fd.hasName = true;
    	    fd.name = addr;
    	}
        if (port != 0)
        {
            fd.port = port;
        }
        connectImpl(fd, inetAddress, port, timeout);
    }
    
    public native void connectImpl(FileDescriptor fd, InetAddress inetAddress, int port, int timeout)
            throws SocketException;
    // end WITH_TAINT_TRACKING

    // begin WITH_TAINT_TRACKING
    public boolean connectNonBlocking(FileDescriptor fd, InetAddress inetAddress, int port) throws IOException {
    	String addr = inetAddress.getHostAddress();
    	if (addr != null) 
        {
    	    fd.hasName = true;
    	    fd.name = addr;
    	}
        if (port != 0)
        {
            fd.port = port;
        }
        return connectNonBlockingImpl(fd, inetAddress, port);
    }
    
    public native boolean connectNonBlockingImpl(FileDescriptor fd, InetAddress inetAddress, int port)
            throws IOException;
    // end WITH_TAINT_TRACKING
    
    public native boolean isConnected(FileDescriptor fd, int timeout) throws IOException;

    public native void socket(FileDescriptor fd, boolean stream) throws SocketException;

    public native void disconnectDatagram(FileDescriptor fd) throws SocketException;

    public native InetAddress getSocketLocalAddress(FileDescriptor fd);

    public native int getSocketLocalPort(FileDescriptor fd);

    public native Object getSocketOption(FileDescriptor fd, int opt) throws SocketException;

    public native void listen(FileDescriptor fd, int backlog) throws SocketException;

    // begin WITH_TAINT_TRACKING
    public int read(FileDescriptor fd, byte[] data, int offset, int count) throws IOException
    {
        if (data == null)
        {
            throw new NullPointerException();
        }

        // Taint
        int bytesRead = readImpl(fd, data, offset, count);
        int tag = Taint.getTaintByteArray(data);
        if (tag == Taint.TAINT_CLEAR)
        {
            Taint.addTaintByteArray(data, Taint.TAINT_INCOMING_DATA);
        }
        else
        {            
			Taint.addTaintByteArray(data, tag);
        }

        // Log
        String addr = (fd.hasName) ? fd.name : "unknown";
        String dstr = new String(data);
        Taint.logNetworkAction("read", tag, addr, fd.port, dstr);

        // Return
        return bytesRead;
    }

    public native int readImpl(FileDescriptor fd, byte[] data, int offset, int count)
            throws IOException;

    public int readDirect(FileDescriptor fd, int address, int count) throws IOException
    {
        String addr = (fd.hasName) ? fd.name : "unknown";
        Taint.logNetworkAction("readDirect", Taint.TAINT_CLEAR, addr, fd.port, "");
        return readDirectImpl(fd, address, count);
    }

    public native int readDirectImpl(FileDescriptor fd, int address, int count) throws IOException;

    public int recv(FileDescriptor fd, DatagramPacket packet,
            byte[] data, int offset, int length,
            boolean peek, boolean connected) throws IOException
    {
        if (data == null)
        {
            throw new NullPointerException();
        }

        // Taint
        int bytesRead = recvImpl(fd, packet, data, offset, length, peek, connected);
        int tag = Taint.getTaintByteArray(data);
        if (tag == Taint.TAINT_CLEAR)
        {
            Taint.addTaintByteArray(data, Taint.TAINT_INCOMING_DATA);
        }
        else
        {            
			Taint.addTaintByteArray(data, tag);
        }
        
        // Log
        String addr = (fd.hasName) ? fd.name : "unknown";
        String dstr = new String(data);
        Taint.logNetworkAction("recv", tag, addr, fd.port, dstr);

        // Return
        return bytesRead;
    }

    public native int recvImpl(FileDescriptor fd, DatagramPacket packet,
            byte[] data, int offset, int length,
            boolean peek, boolean connected) throws IOException;
    

    public int recvDirect(FileDescriptor fd, DatagramPacket packet,
            int address, int offset, int length,
            boolean peek, boolean connected) throws IOException
    {
        String addr = (fd.hasName) ? fd.name : "unknown";
        Taint.logNetworkAction("recvDirect", Taint.TAINT_CLEAR, addr, fd.port, "");
        return recvDirectImpl(fd, packet, address, offset, length, peek, connected);
    }

    public native int recvDirectImpl(FileDescriptor fd, DatagramPacket packet,
            int address, int offset, int length,
            boolean peek, boolean connected) throws IOException;

    // end WITH_TAINT_TRACKING

    public boolean select(FileDescriptor[] readFDs, FileDescriptor[] writeFDs,
            int numReadable, int numWritable, long timeout, int[] flags)
            throws SocketException {
        if (numReadable < 0 || numWritable < 0) {
            throw new IllegalArgumentException();
        }

        int total = numReadable + numWritable;
        if (total == 0) {
            return true;
        }

        return selectImpl(readFDs, writeFDs, numReadable, numWritable, flags, timeout);
    }

    static native boolean selectImpl(FileDescriptor[] readfd,
            FileDescriptor[] writefd, int cread, int cwirte, int[] flags,
            long timeout);

    // begin WITH_TAINT_TRACKING
    public int send(FileDescriptor fd, byte[] data, int offset, int length,
            int port, InetAddress inetAddress) throws IOException {
        // Taint
    	int tag = Taint.getTaintByteArray(data);

        // Log
        String addr = (fd.hasName) ? fd.name : "unknown";
        String dstr = new String(data);
        Taint.logNetworkAction("send", tag, addr, port, dstr);

        // Return
    	return sendImpl(fd, data, offset, length, port, inetAddress);
    }
    
    public native int sendImpl(FileDescriptor fd, byte[] data, int offset, int length,
            int port, InetAddress inetAddress) throws IOException;
    
    public int sendDirect(FileDescriptor fd, int address, int offset, int length,
            int port, InetAddress inetAddress) throws IOException
    {
        String addr = (fd.hasName) ? fd.name : "unknown";
        Taint.logNetworkAction("sendDirect", Taint.TAINT_CLEAR, addr, port, "");
        return sendDirectImpl(fd, address, offset, length, port, inetAddress);
    }

    public native int sendDirectImpl(FileDescriptor fd, int address, int offset, int length,
            int port, InetAddress inetAddress) throws IOException;

	public void sendUrgentData(FileDescriptor fd, byte value) {
        // Taint
		int tag = Taint.getTaintByte(value);

        // Log
        String addr = (fd.hasName) ? fd.name : "unknown";
        String dstr = Byte.toString(value);
        Taint.logNetworkAction("sendUrgentData", tag, addr, fd.port, dstr);

        // Return
		sendUrgentDataImpl(fd, value);
	}

    public native void sendUrgentDataImpl(FileDescriptor fd, byte value);
    // end WITH_TAINT_TRACKING

    public native void setInetAddress(InetAddress sender, byte[] address);

    public native void setSocketOption(FileDescriptor fd, int opt, Object optVal)
            throws SocketException;

    public native void shutdownInput(FileDescriptor fd) throws IOException;

    public native void shutdownOutput(FileDescriptor fd) throws IOException;

    public native void close(FileDescriptor fd) throws IOException;

	// begin WITH_TAINT_TRACKING
	public int write(FileDescriptor fd, byte[] data, int offset, int count) throws IOException 
    {
        // Taint
		int tag = Taint.getTaintByteArray(data);

        // Log
        String addr = (fd.hasName) ? fd.name : "unknown";
        String dstr = new String(data);
        Taint.logNetworkAction("write", tag, addr, fd.port, dstr);

        // Return
		return writeImpl(fd, data, offset, count);
	}
   
    public native int writeImpl(FileDescriptor fd, byte[] data, int offset, int count) throws IOException;    

    public int writeDirect(FileDescriptor fd, int address, int offset, int count) throws IOException
    {
        String addr = (fd.hasName) ? fd.name : "unknown";
        Taint.logNetworkAction("writeDirect", Taint.TAINT_CLEAR, addr, fd.port, "");
        return writeDirectImpl(fd, address, offset, count);
    }

    public native int writeDirectImpl(FileDescriptor fd, int address, int offset, int count)
            throws IOException;
    // end WITH_TAINT_TRACKING
}
