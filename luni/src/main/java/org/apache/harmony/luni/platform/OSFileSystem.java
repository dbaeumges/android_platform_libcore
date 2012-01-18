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

// BEGIN android-note
// address length was changed from long to int for performance reasons.
// END android-note

package org.apache.harmony.luni.platform;

import java.io.FileDescriptor;
import java.io.FileNotFoundException;
import java.io.IOException;

//begin WITH_TAINT_TRACKING
import dalvik.system.Taint;
import dalvik.system.TaintLog;
import java.util.Random;
// end WITH_TAINT_TRACKING

class OSFileSystem implements IFileSystem {

    private static final OSFileSystem singleton = new OSFileSystem();

    // begin WITH_TAINT_TRACKING
    private int taintLogId;
    // end WITH_TAINT_TRACKING

    public static OSFileSystem getOSFileSystem() {
        return singleton;
    }

    private OSFileSystem() {
    }

    private final void validateLockArgs(int type, long start, long length) {
        if ((type != IFileSystem.SHARED_LOCK_TYPE)
                && (type != IFileSystem.EXCLUSIVE_LOCK_TYPE)) {
            throw new IllegalArgumentException("Illegal lock type requested.");
        }

        // Start position
        if (start < 0) {
            throw new IllegalArgumentException("start < 0");
        }

        // Length of lock stretch
        if (length < 0) {
            throw new IllegalArgumentException("length < 0");
        }
    }

    private native int lockImpl(int fd, long start, long length, int type, boolean wait);

    /**
     * Returns the granularity for virtual memory allocation.
     * Note that this value for Windows differs from the one for the
     * page size (64K and 4K respectively).
     */
    public native int getAllocGranularity();

    public native long length(int fd);

    public boolean lock(int fd, long start, long length, int type, boolean waitFlag)
            throws IOException {
        // Validate arguments
        validateLockArgs(type, start, length);
        int result = lockImpl(fd, start, length, type, waitFlag);
        return result != -1;
    }

    private native void unlockImpl(int fd, long start, long length) throws IOException;

    public void unlock(int fd, long start, long length) throws IOException {
        // Validate arguments
        validateLockArgs(IFileSystem.SHARED_LOCK_TYPE, start, length);
        unlockImpl(fd, start, length);
    }

    public native void fsync(int fd, boolean metadata) throws IOException;

    /*
     * File position seeking.
     */
    public native long seek(int fd, long offset, int whence) throws IOException;

    // begin WITH_TAINT_TRACKING
    /*
     * Direct read/write APIs work on addresses.
     */
    public long readDirect(int fd, int address, int offset, int length)
    {
        TaintLog.getInstance().logFileSystem(TaintLog.FS_READ_DIRECT_ACTION, Taint.TAINT_CLEAR, fd, taintLogId, "");
        return readDirectImpl(fd, address, offset, length);
    }

    public native long readDirectImpl(int fd, int address, int offset, int length);

    public long writeDirect(int fd, int address, int offset, int length)
    {
        TaintLog.getInstance().logFileSystem(TaintLog.FS_WRITE_DIRECT_ACTION, Taint.TAINT_CLEAR, fd, taintLogId, "");
        return writeDirectImpl(fd, address, offset, length);
    }

    public native long writeDirectImpl(int fd, int address, int offset, int length);

    /*
     * Indirect read/writes work on byte[]'s
     */	
	public long read(int fileDescriptor, byte[] bytes, int offset, int length)
			throws IOException {
		if (bytes == null) {
			throw new NullPointerException();
		}
		long bytesRead = readImpl(fileDescriptor, bytes, offset, length);
		int tag = Taint.getTaintFile(fileDescriptor);
        String dstr = new String(bytes);
        TaintLog.getInstance().logFileSystem(TaintLog.FS_READ_ACTION, tag, fileDescriptor, taintLogId, dstr);
        Taint.addTaintByteArray(bytes, tag);
		return bytesRead;
	}

	public long write(int fileDescriptor, byte[] bytes, int offset, int length)
			throws IOException {
		if (bytes == null) {
			throw new NullPointerException();
		}
		long bytesWritten = writeImpl(fileDescriptor, bytes, offset, length);
		int tag = Taint.getTaintByteArray(bytes);
        String dstr = new String(bytes);		
        TaintLog.getInstance().logFileSystem(TaintLog.FS_WRITE_ACTION, tag, fileDescriptor, taintLogId, dstr);
        Taint.addTaintFile(fileDescriptor, tag);
		return bytesWritten;
	}
    
    public native long readImpl(int fd, byte[] bytes, int offset, int length) throws IOException;

    public native long writeImpl(int fd, byte[] bytes, int offset, int length) throws IOException;    

    /*
     * Scatter/gather calls.
     */
    public long readv(int fd, int[] addresses, int[] offsets, int[] lengths, int size)
            throws IOException
    {
        TaintLog.getInstance().logFileSystem(TaintLog.FS_READV_ACTION, Taint.TAINT_CLEAR, fd, taintLogId, "");
        return readvImpl(fd, addresses, offsets, lengths, size);
    }

    public native long readvImpl(int fd, int[] addresses, int[] offsets, int[] lengths, int size)
            throws IOException;

    public long writev(int fd, int[] addresses, int[] offsets, int[] lengths, int size)
            throws IOException
    {
        TaintLog.getInstance().logFileSystem(TaintLog.FS_WRITEV_ACTION, Taint.TAINT_CLEAR, fd, taintLogId, "");
        return writevImpl(fd, addresses, offsets, lengths, size);
    }

    public native long writevImpl(int fd, int[] addresses, int[] offsets, int[] lengths, int size)
            throws IOException;
    // end WITH_TAINT_TRACKING

    public native void truncate(int fd, long size) throws IOException;

    // begin WITH_TAINT_TRACKING
    public int open(String path, int mode) throws FileNotFoundException
    {
        Random aRandomGen = new Random();
        this.taintLogId = aRandomGen.nextInt();  
        return openImpl(path, mode);
    }

    public native int openImpl(String path, int mode) throws FileNotFoundException;
    // end WITH_TAINT_TRACKING

    public native long transfer(int fd, FileDescriptor sd, long offset, long count)
            throws IOException;

    public native int ioctlAvailable(FileDescriptor fileDescriptor) throws IOException;
}
