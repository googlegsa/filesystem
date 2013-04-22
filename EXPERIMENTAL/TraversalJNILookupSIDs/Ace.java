import java.util.*;

public class Ace {
  enum AceType {
    ACCESS_ALLOWED(0),
    ACCESS_DENIED(1),
    ACCESS_ALLOWED_OBJECT(5),
    ACCESS_DENIED_OBJECT(6),
    UNKNOWN(-1);

    private static final Map<Integer, AceType> intToAceMap = new HashMap<>();
    static {
      for (AceType type : AceType.values()) {
        intToAceMap.put(type.value, type);
      }
    }

    private final int value;

    AceType(int value) {
      this.value = value;
    }

    public static AceType fromInt(int i) {
      AceType type = intToAceMap.get(Integer.valueOf(i));
      if (type == null) return AceType.UNKNOWN;
      return type;
    }
  }

  private static final int OBJECT_INHERIT_FLAG = 0x01;  // OI
  private static final int CONTAINER_INHERIT_FLAG = 0x02;  // CI
  private static final int NO_PROPAGATE_INHERIT_FLAG = 0x04;  // NP
  private static final int INHERIT_ONLY_FLAG = 0x08;  // IO
  private static final int INHERITED_ACE_FLAG = 0x10;  // I

  private final int flags;
  private final AceType type;
  private final String sid;

  public Ace(int flags, int type, String sid) {
    this.flags = flags;
    this.type = AceType.fromInt(type);
    this.sid = sid;
  }

  public AceType getType() {
    return type;
  }

  public String getSid() {
    return sid;
  }

  public boolean isObjectInherit() {
    return (flags & OBJECT_INHERIT_FLAG) > 0;
  }

  public boolean isContainerInherit() {
    return (flags & CONTAINER_INHERIT_FLAG) > 0;
  }

  public boolean isNoPropagateInherit() {
    return (flags & NO_PROPAGATE_INHERIT_FLAG) > 0;
  }

  public boolean isInheritOnly() {
    return (flags & INHERIT_ONLY_FLAG) > 0;
  }

  public boolean isInheritedAce() {
    return (flags & INHERITED_ACE_FLAG) > 0;
  }

  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("SID: ").append(sid).append("; ");
    sb.append("TYPE: ").append(type.toString()).append("; ");
    sb.append("FLAGS: ");
    if (isObjectInherit()) sb.append("OI");
    if (isContainerInherit()) sb.append("CI");
    if (isNoPropagateInherit()) sb.append("NP");
    if (isInheritOnly()) sb.append("IO");
    if (isInheritedAce()) sb.append("I");
    return sb.toString();
  }
}
