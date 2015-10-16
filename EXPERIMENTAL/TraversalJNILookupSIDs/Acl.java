import jcifs.smb.*;

import java.io.*;
import java.nio.ByteBuffer;
import java.util.*;

public class Acl {
  public static final String NAME = "system.cifs_acl";
  public static final int BUFFER_SIZE = 1024;

  public static final int UINT_MAX = 0xFFFF;
  /** number of authority fields */
  public static final int NUM_AUTHS = 6;
  public static final int SIZEOF_CIFS_CTRL_ACL = 8;

  private SidLookup lookup;

  private String owner;
  private String group;

  private int revision;
  private int osidoffset;
  private int gsidoffset;
  private int dacloffset;
  private List<Ace> aces;

  static {
    System.loadLibrary("acl");
  }

  public Acl(String path, SidLookup lookup) throws IOException, SmbException {
    this.lookup = lookup;
    ByteBuffer buffer = readRaw(path);

    revision = extractInt(2, 2, buffer);
    osidoffset = extractInt(4, 4, buffer);
    gsidoffset = extractInt(8, 4, buffer);
    dacloffset = extractInt(16, 4, buffer);

    owner = lookup.resolve(extractSid(osidoffset, buffer));
    group = lookup.resolve(extractSid(gsidoffset, buffer));

    aces = new LinkedList<>();
    extractAces(dacloffset, buffer);
  }

  private native int getxattr(String path, String attributeName, ByteBuffer buffer);

  public String getOwner() {
    return owner;
  }

  public String getGroup() {
    return group;
  }

  // TODO: immutability
  public List<Ace> getAces() {
    return aces;
  }

  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("OWNER: ").append(owner).append("\n");
    sb.append("GROUP: ").append(group).append("\n");
    sb.append("ACES:\n");
    for (Ace ace : aces) {
      sb.append("\t").append(ace.toString()).append("\n");
    }
    return sb.toString();
  }

  private ByteBuffer readRaw(String path) {
    ByteBuffer buffer = ByteBuffer.allocateDirect(BUFFER_SIZE);
    getxattr(path, NAME, buffer);
    return buffer;
  }

  private int extractInt(int offset, int bytes, ByteBuffer buffer) {
    int value = 0;

    for (int i = (offset + bytes - 1); i >= offset; i--) {
      value |= (buffer.get(i) & 0xff) << ((i - offset) * 8);
    }

    return value;
  }

  private long extractLong(int offset, int bytes, ByteBuffer buffer) {
    long value = buffer.get(offset + bytes - 1) & 0xff;
    value <<= 8 * (bytes - 1);

    for (int i = (offset + bytes - 2); i >= offset; i--) {
      value |= (buffer.get(i) & 0xff) << ((i - offset) * 8);
    }

    return value;
  }

  private String extractSid(int offset, ByteBuffer buffer) {
    StringBuilder sb = new StringBuilder("S-");

    // revision, bytes: offset
    int revision = extractInt(offset, 1, buffer);
    sb.append(revision);
    // number of subauthorities, bytes: offset+1
    int subauth_num = extractInt(offset+1, 1, buffer);
    // authorities, bytes: offset+1+1:offset+1+NUM_AUTHS
    long id_auth_val = buffer.get(offset + 1 + 6) & 0xff;
    id_auth_val += (buffer.get(offset + 1 + 5) & 0xff) << 8;
    id_auth_val += (buffer.get(offset + 1 + 4) & 0xff) << 16;
    id_auth_val += (buffer.get(offset + 1 + 3) & 0xff) << 24;
    id_auth_val += (buffer.get(offset + 1 + 2) & 0xff) << 32;
    id_auth_val += (buffer.get(offset + 1 + 1) & 0xff) << 48;

    if (id_auth_val <= UINT_MAX) {
      sb.append("-" + id_auth_val);
    } else {
      sb.append("-0x" + Long.toHexString(id_auth_val));
    }
    // actual subauthorities, bytes: offset+2+NUM_AUTHS+1:subauth_num
    long val = 0;
    int subauth_array_offset = offset + 1 + NUM_AUTHS + 1;
    for (int i = 0; i < subauth_num; i++) {
      val = extractLong(subauth_array_offset, 4, buffer);
      sb.append("-" + val);
      subauth_array_offset += 4;
    }
    return sb.toString();
  }

  private void extractAces(int offset, ByteBuffer buffer) throws IOException, SmbException {
    int acl_size = extractInt(offset + 2, 2, buffer);
    long ace_num = extractLong(offset + 4, 4, buffer);
    int ace_offset = offset + SIZEOF_CIFS_CTRL_ACL;

    int ace_size = SIZEOF_CIFS_CTRL_ACL;
    if (ace_num > 0) {
      for (int i = 0; i < ace_num; i++) {
        int type = buffer.get(ace_offset);
        int flags = buffer.get(ace_offset + 1);
        ace_size = extractInt(ace_offset + 2, 2, buffer);
        aces.add(new Ace(flags, type, lookup.resolve(extractSid(ace_offset + 8, buffer))));
        ace_offset += ace_size;
      }
    }
  }

  public static void main(String[] args) throws Exception {
    SidLookup lookup = new SidLookup("172.25.51.36", "gsa-connectors", "Administrator", "p@assword123");
    Acl acl = new Acl("/mnt/10M-Windows/PDF/site11/0/11005.pdf", lookup);
    System.out.println(acl);
  }
}
