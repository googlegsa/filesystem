import jcifs.smb.*;

import java.io.*;
import java.util.*;

public class SidLookup {
  private static final int MAX_TRIES = 5;
  private Map<String, String> sidCache;

  private final String dc;
  private final NtlmPasswordAuthentication creds;

  public SidLookup(String dc, String domain, String username, String password) {
    this.dc = dc;
    this.creds = new NtlmPasswordAuthentication(domain, username, password);
    this.sidCache = new HashMap<>();
  }

  public String resolve(String sid) throws IOException, SmbException {
    String cached = sidCache.get(sid);
    if (cached != null) {
      return cached;
    }

    int tries = 0;
    while (true) {
      try {
        SID sidObject = new SID(sid);
        sidObject.resolve(dc, creds);
        sidCache.put(sid, sidObject.toDisplayString());
        return sidObject.toDisplayString();
      } catch (SmbException e) {
        if (tries == MAX_TRIES) {
          throw e;
        }
      }
      tries++;
    }
  }

  public static void main(String[] argv) throws Exception {
    SidLookup lookup = new SidLookup("172.25.51.36", "gsa-connectors", "Administrator", "p@assword123");
    System.out.println(lookup.resolve("S-1-5-21-3993744865-3521423997-1479072767-513"));
    System.out.println(lookup.resolve("S-1-5-21-3993744865-3521423997-1479072767-513"));
  }
}
