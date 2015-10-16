import static java.nio.file.FileVisitResult.*;

import java.io.*;
import java.nio.*;
import java.nio.channels.*;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.util.*;

public class Main {
  public static final int FEED_SIZE = 4000;
  public static final int BUFFER_SIZE = 1024 * 64;
  public static final int THREADS = 20;
  public static final int STAT_FREQ_SEC = 60 * 20;  // every 20 minutes
  public static final String encoding = System.getProperty("file.encoding");

  private SidLookup lookup = new SidLookup(
      "172.25.51.36", "gsa-connectors", "Administrator", "p@assword123");

  private class TestTraverserRunner implements Runnable {
    private TestTraverser traverser;
    private Path path;

    public TestTraverserRunner(String path, int feedSize) {
      traverser = new TestTraverser(feedSize);
      this.path = Paths.get(path);
    }

    public void run() {
      try {
        Files.walkFileTree(path, traverser);
      } catch (Exception e) {
        System.out.println(e);
      }
    }
  }

  private class TestTraverser extends SimpleFileVisitor<Path> {
    private final int feedBufferSize;
    private LinkedList<Record> records;
    private int fileCount;
    private int totalFileCount;
    private int dirCount;
    private long startMillis;

    public TestTraverser(int feedBufferSize) {
      this.feedBufferSize = feedBufferSize;
      records = new LinkedList<>();
      startMillis = System.currentTimeMillis();
    }

    public FileVisitResult visitFile(Path file, BasicFileAttributes attr) {
      fileCount++;
      totalFileCount++;

      Record record = new Record();
      record.fullPath = file.toString();
      try (SeekableByteChannel sbc = Files.newByteChannel(file)) {
        ByteBuffer buf = ByteBuffer.allocate(BUFFER_SIZE);
        while (sbc.read(buf) > 0);
      } catch (Exception e) {
        System.out.println("FAILED GETTING CONTENT");
      }
      try {
        record.aclInfo = new Acl(file.toString(), lookup);
      } catch (Exception e) {
        System.out.println("AAA ACL RESOLUTION FAILED");
        e.printStackTrace();
      }
      
      record.isFile = true;

      record.creationTime = attr.creationTime();
      record.lastAccessTime = attr.lastAccessTime();
      record.lastModifiedTime = attr.lastModifiedTime();

      records.add(record);
      if (records.size() > feedBufferSize) records.remove();

      // print out rate statistics every X seconds
      if (System.currentTimeMillis() - startMillis >= STAT_FREQ_SEC * 1000) {
        System.out.println("CURRENT RATE: " + (((double)fileCount) / STAT_FREQ_SEC) + " docs/sec; Total files: " + totalFileCount);
        startMillis = System.currentTimeMillis();
        fileCount = 0;

        Runtime r = Runtime.getRuntime();
        System.out.println(Thread.currentThread().getName() + " MEMORY USAGE: " + (r.totalMemory() - r.freeMemory()) + " bytes");
      }

      return CONTINUE;
    }

    @Override
    public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attr) {
      dirCount++;

      Record record = new Record();
      record.fullPath = dir.toString();
      try {
        record.aclInfo = new Acl(dir.toString(), lookup);
      } catch (Exception e) {
        System.out.println("AAA ACL RESOLUTION FAILED");
        e.printStackTrace();
      }

      record.creationTime = attr.creationTime();
      record.lastAccessTime = attr.lastAccessTime();
      record.lastModifiedTime = attr.lastModifiedTime();

      records.add(record);
      if (records.size() > feedBufferSize) records.remove();

      return CONTINUE;
    }

    @Override
    public FileVisitResult visitFileFailed(Path file, IOException exc) {
      System.err.println(exc);
      return CONTINUE;
    }
  }

  private class Record {
    public Acl aclInfo;
    public String fullPath;
    public boolean isFile;
    public FileTime creationTime;
    public FileTime lastAccessTime;
    public FileTime lastModifiedTime;

    @Override
    public String toString() {
      String start;
      if (isFile) start = "FILE path: ";
      else start = "DIR path: ";

      return start + fullPath + "\n"
         + "ACL info: " + aclInfo + "\n"
         + "Created: " + creationTime + "\n"
         + "Last Modified: " + lastModifiedTime + "\n"
         + "Last Accessed: " + lastAccessTime;
    }
  }

  public static void main(String[] args) throws Exception {
    Main main = new Main();
    Runnable runner;
    for (int i = 0; i < THREADS; i++) {
      runner = main.new TestTraverserRunner(args[0], FEED_SIZE);
      new Thread(runner).start();
      //Thread.sleep(1000 * 60 * 5);
    }
  }
}
