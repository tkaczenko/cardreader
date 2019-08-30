/*
 * JMRTD - A Java API for accessing machine readable travel documents.
 *
 * Copyright (C) 2006 - 2018  The JMRTD team
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * $Id: FragmentBuffer.java 1808 2019-03-07 21:32:19Z martijno $
 */

package org.jmrtd.io;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;

/**
 * A buffer that can be partially filled.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1808 $
 */
public class FragmentBuffer implements Serializable {

  private static final long serialVersionUID = -3510872461790499721L;

  private static final int DEFAULT_SIZE = 2000;

  /** Buffer with the actual bytes. */
  private byte[] buffer;

  /** Administration of which parts of buffer are filled. */
  private Collection<Fragment> fragments;

  /**
   * Creates a fragment buffer with default size.
   */
  public FragmentBuffer() {
    this(DEFAULT_SIZE);
  }

  /**
   * Creates a fragment buffer.
   *
   * @param length the length of the buffer
   */
  public FragmentBuffer(int length) {
    this.buffer = new byte[length];
    this.fragments = new HashSet<Fragment>();
  }

  /**
   * Updates this buffer based on the given buffer.
   *
   * @param other some other fragment buffer
   */
  public synchronized void updateFrom(FragmentBuffer other) {
    for (Fragment otherFragment: other.fragments) {
      addFragment(otherFragment.offset, other.buffer, otherFragment.offset, otherFragment.length);
    }
  }

  /**
   * Adds a fragment containing the given byte.
   *
   * @param offset the offset
   * @param b the byte to insert
   */
  public synchronized void addFragment(int offset, byte b) {
    /*
     * NOTE: This can be done more efficiently for common case resulting from InputStreamBuffer read,
     * scan all fragments and extend neighboring one.
     */
    addFragment(offset, new byte[] { b });
  }

  /**
   * Adds a fragment of bytes at a specific offset to this file.
   *
   * @param offset the fragment offset
   * @param bytes the bytes from which fragment content will be copied
   */
  public synchronized void addFragment(int offset, byte[] bytes) {
    addFragment(offset, bytes, 0, bytes.length);
  }

  /**
   * Adds a fragment of bytes at a specific offset to this file.
   *
   * @param offset the fragment offset
   * @param bytes the bytes from which fragment contents will be copied
   * @param srcOffset the offset within bytes where the contents of the fragment start
   * @param srcLength the length of the fragment
   */
  public synchronized void addFragment(int offset, byte[] bytes, int srcOffset, int srcLength) {
    if (offset + srcLength > buffer.length) {
      setLength(2 * Math.max(offset + srcLength, buffer.length));
    }

    System.arraycopy(bytes, srcOffset, buffer, offset, srcLength);
    int thisOffset = offset;
    int thisLength = srcLength;
    final Collection<Fragment> otherFragments = new ArrayList<Fragment>(fragments);
    for (Fragment other: otherFragments) {
      /* On partial overlap we change this fragment, possibly remove the other overlapping fragments we encounter. */
      if (other.getOffset() <= thisOffset && thisOffset + thisLength <= other.getOffset() + other.getLength()) {
        /*
         * [...other fragment.........]
         *    [...this fragment...]
         *
         * This fragment is already contained in other. Don't add and return immediately.
         */
        return;
      } else if (other.getOffset() <= thisOffset && thisOffset <= other.getOffset() + other.getLength()) {
        /*
         * [...other fragment...]
         *         [...this fragment...]
         *
         * This fragment is partially contained in other. Extend this fragment to size of other, remove other.
         */
        thisLength = thisOffset + thisLength - other.getOffset();
        thisOffset = other.getOffset();
        fragments.remove(other);
      }  else if (thisOffset <= other.getOffset() && other.getOffset() + other.getLength() <= thisOffset + thisLength) {
        /*
         *    [...other fragment...]
         * [...this fragment...........]
         *
         * The other fragment is contained in this fragment. Remove other.
         */
        fragments.remove(other);
      } else if (thisOffset <= other.getOffset() && other.getOffset() <= thisOffset + thisLength) {
        /*
         *        [...other fragment...]
         * [...this fragment...]
         *
         * This fragment is partially contained in other. Extend this fragment to size of other, remove other.
         */
        thisLength = other.getOffset() + other.getLength() - thisOffset;
        fragments.remove(other);
      }
    }
    fragments.add(Fragment.getInstance(thisOffset, thisLength));
  }

  /**
   * Returns the position within the buffer.
   * This is the upper limit of the farthest fragment read so far.
   *
   * @return the position within the buffer
   */
  public synchronized int getPosition() {
    int result = 0;
    for (int i = 0; i < buffer.length; i++) {
      if (isCoveredByFragment(i)) {
        result = i + 1;
      }
    }
    return result;
  }

  /**
   * Returns the number of bytes currently buffered.
   *
   * @return the number of bytes currently buffered
   */
  public synchronized int getBytesBuffered() {
    int result = 0;
    for (int i = 0; i < buffer.length; i++) {
      if (isCoveredByFragment(i)) {
        result++;
      }
    }
    return result;
  }

  /**
   * Checks whether the byte at the given offset is covered
   * by a fragment.
   *
   * @param offset the offset
   *
   * @return a boolean indicating whether the byte at the given offset is covered
   */
  public synchronized boolean isCoveredByFragment(int offset) {
    return isCoveredByFragment(offset, 1);
  }

  /**
   * Checks whether the segment specified by the given offset and length
   * is completely covered by fragments.
   *
   * @param offset the given offset
   * @param length the given length
   *
   * @return a boolean indicating whether the specified segment is fully covered
   */
  public synchronized boolean isCoveredByFragment(int offset, int length) {
    for (Fragment fragment: fragments) {
      int left = fragment.getOffset();
      int right = fragment.getOffset() + fragment.getLength();
      if (left <= offset && offset + length <= right) {
        return true;
      }
    }
    return false;
  }

  /**
   * Calculates the number of bytes left in the buffer starting from index <code>index</code>.
   *
   * @param index the index
   *
   * @return the number of bytes left in the buffer
   */
  public synchronized int getBufferedLength(int index) {
    int result = 0;
    if (index >= buffer.length) {
      return 0;
    }

    for (Fragment fragment: fragments) {
      int left = fragment.getOffset();
      int right = fragment.getOffset() + fragment.getLength();
      if (left <= index && index < right) {
        int newResult = right - index;
        if (newResult > result) {
          result = newResult;
        }
      }
    }
    return result;
  }

  /**
   * Returns the fragments of this buffer.
   *
   * @return the fragments
   */
  public Collection<Fragment> getFragments() {
    return fragments;
  }

  /**
   * Returns the current buffer.
   *
   * @return the buffer
   */
  public byte[] getBuffer() {
    return buffer;
  }

  /**
   * Returns the buffer (the size of the underlying byte array).
   *
   * @return the size of the buffer
   */
  public  int getLength() {
    synchronized(this) {
      return buffer.length;
    }
  }

  /**
   * Returns the smallest fragment that contains <code>offset</code> and <code>offset + length</code>
   * that has <strong>not</strong> been buffered in this buffer.
   *
   * @param offset the offset
   * @param length the length
   *
   * @return the fragment that has not yet been buffered
   */
  public synchronized Fragment getSmallestUnbufferedFragment(int offset, int length) {
    int thisOffset = offset;
    int thisLength = length;
    for (Fragment other: fragments) {
      /* On partial overlap we change this fragment, removing sections already buffered. */
      if (other.getOffset() <= thisOffset && thisOffset + thisLength <= other.getOffset() + other.getLength()) {
        /*
         * [...other fragment.........]
         *    [...this fragment...]
         *
         * This fragment is already contained in other. Don't add and return immediately.
         */
        thisLength = 0; /* NOTE: we don't care about offset */
        break;
      } else if (other.getOffset() <= thisOffset && thisOffset < other.getOffset() + other.getLength()) {
        /*
         * [...other fragment...]
         *         [...this fragment...]
         *
         * This fragment is partially contained in other. Only fetch the trailing part of this fragment.
         */
        int newOffset = other.getOffset() + other.getLength();
        int newLength = thisOffset + thisLength - newOffset;
        thisOffset = newOffset;
        thisLength = newLength;
      }  else if (thisOffset <= other.getOffset() && other.getOffset() + other.getLength() <= thisOffset + thisLength) {
        /*
         *    [...other fragment...]
         * [...this fragment...........]
         *
         * The other fragment is contained in this fragment. We send this fragment as is.
         */
        continue;
      } else if (offset <= other.getOffset() && other.getOffset() < thisOffset + thisLength) {
        /*
         *        [...other fragment...]
         * [...this fragment...]
         *
         * This fragment is partially contained in other. Only send the leading part of this fragment.
         */
        thisLength = other.getOffset() - thisOffset;
      }
    }
    return Fragment.getInstance(thisOffset, thisLength);
  }

  @Override
  public synchronized String toString() {
    return "FragmentBuffer [" + buffer.length + ", " + fragments + "]";
  }

  @Override
  public synchronized boolean equals(Object otherObject) {
    if (otherObject == null) {
      return false;
    }
    if (otherObject == this) {
      return true;
    }
    if (!otherObject.getClass().equals(FragmentBuffer.class)) {
      return false;
    }
    FragmentBuffer otherBuffer = (FragmentBuffer) otherObject;
    if (otherBuffer.buffer == null && this.buffer != null) {
      return false;
    }
    if (otherBuffer.buffer != null && this.buffer == null) {
      return false;
    }
    if (otherBuffer.fragments == null && this.fragments != null) {
      return false;
    }
    if (otherBuffer.fragments != null && this.fragments == null) {
      return false;
    }

    return Arrays.equals(otherBuffer.buffer, this.buffer) && otherBuffer.fragments.equals(this.fragments);
  }

  @Override
  public int hashCode() {
    return 3 * Arrays.hashCode(buffer) + 2 * fragments.hashCode() + 7;
  }

  /**
   * Sets the capacity of the buffer.
   * This has no effect for lengths smaller than the current buffer capacity.
   *
   * @param length the proposed new capacity of the buffer
   */
  private void setLength(int length) {
    synchronized(this) {
      if (length <= buffer.length) {
        return;
      }

      byte[] newBuffer = new byte[length];
      System.arraycopy(this.buffer, 0, newBuffer, 0, this.buffer.length);
      this.buffer = newBuffer;
    }
  }

  /**
   * Fragments encapsulate pairs of offset and length.
   */
  public static class Fragment implements Serializable {

    private static final long serialVersionUID = -3795931618553980328L;

    private int offset;
    private int length;

    /**
     * Constructs a fragment.
     *
     * @param offset the offset within the buffer
     * @param length the length of the fragment
     */
    private Fragment(int offset, int length) {
      this.offset = offset;
      this.length = length;
    }

    /**
     * Returns a fragment instance.
     *
     * @param offset the offset within the buffer
     * @param length the length of the fragment
     *
     * @return the new fragment
     */
    public static Fragment getInstance(int offset, int length) {
      return new Fragment(offset, length);
    }

    /**
     * Returns this fragment's offset within the buffer.
     *
     * @return the offset of the fragment
     */
    public int getOffset() {
      return offset;
    }

    /**
     * Returns the length of the fragment.
     *
     * @return the length of the fragment
     */
    public int getLength() {
      return length;
    }

    @Override
    public String toString() {
      return "[" + offset + " .. " + (offset + length - 1)  + " (" + length + ")]";
    }

    @Override
    public boolean equals(Object otherObject) {
      if (otherObject == null) {
        return false;
      }
      if (otherObject == this) {
        return true;
      }
      if (!otherObject.getClass().equals(Fragment.class)) {
        return false;
      }

      Fragment otherFragment = (Fragment)otherObject;
      return otherFragment.offset == offset && otherFragment.length == length;
    }

    @Override
    public int hashCode() {
      return 2 * offset + 3 * length + 5;
    }
  }
}
