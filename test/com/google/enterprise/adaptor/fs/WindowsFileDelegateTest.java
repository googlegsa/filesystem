// Copyright 2014 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.enterprise.adaptor.fs;

import com.google.common.base.Charsets;
import com.google.common.base.Preconditions;
import com.google.common.collect.Sets;
import com.google.common.io.CharStreams;

import static org.junit.Assert.*;
import static org.junit.Assume.*;

import org.junit.*;
import org.junit.rules.ExpectedException;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/** Tests for {@link WindowsFileDelegate} */
public class WindowsFileDelegateTest {

  @BeforeClass
  public static void checkIfRunningOnWindows() {
    TestHelper.assumeOsIsWindows();
  }

  private FileDelegate delegate = new WindowsFileDelegate();
  private BlockingQueue<Path> queue = new LinkedBlockingQueue<Path>();
  private Path tempRoot;

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  @Rule
  public TemporaryFolder temp = new TemporaryFolder();

  @Before
  public void setUp() throws Exception {
    tempRoot = temp.getRoot().getCanonicalFile().toPath();
  }
    
  @After
  public void tearDown() {
    delegate.destroy();
  }

  private Path newTempDir(String name) throws IOException {
    return temp.newFolder(name).toPath().toRealPath();
  }

  private Path newTempFile(String name) throws IOException {
    return temp.newFile(name).toPath().toRealPath();
  }

  private Path newTempFile(Path parent, String name) throws IOException {
    Preconditions.checkArgument(parent.startsWith(tempRoot));
    return Files.createFile(parent.resolve(name));
  }

  @Test
  public void testNewDocIdLocalFiles() throws Exception {
    Path dir = newTempDir("testDir");
    Path file = newTempFile(dir, "test");

    String id = delegate.newDocId(tempRoot).getUniqueId();
    assertTrue(id.startsWith(tempRoot.toString().replace('\\', '/')));
    assertTrue(id.endsWith("/"));

    id = delegate.newDocId(dir).getUniqueId();
    assertTrue(id.startsWith(tempRoot.toString().replace('\\', '/')));
    assertTrue(id.startsWith(dir.toString().replace('\\', '/')));
    assertTrue(id.endsWith("/"));

    id = delegate.newDocId(file).getUniqueId();
    assertTrue(id.startsWith(tempRoot.toString().replace('\\', '/')));
    assertTrue(id.startsWith(dir.toString().replace('\\', '/')));
    assertTrue(id.equals(file.toString().replace('\\', '/')));
    assertFalse(id.endsWith("/"));
  }

  @Test
  public void testNewDocIdVirtualUncPaths() throws Exception {
    assertEquals("\\\\host/share",
        delegate.newDocId(Paths.get("\\\\host\\share")).getUniqueId());
    assertEquals("\\\\host/share",
        delegate.newDocId(Paths.get("\\\\host\\share\\")).getUniqueId());
    assertEquals("\\\\host/share/foo/bar",
        delegate.newDocId(Paths.get("\\\\host\\share\\foo\\bar"))
        .getUniqueId());
  }

  @Test
  public void testNewDocIdLocalUncPaths() throws Exception {
    String uncTempRoot = getTempRootAsUncPath();
    assumeNotNull(uncTempRoot);
    Path tempRoot = Paths.get(uncTempRoot);
    String expectedTempRootId = "\\\\" + uncTempRoot.substring(2)
        .replace('\\', '/') + "/";

    assertEquals(expectedTempRootId,
        delegate.newDocId(tempRoot).getUniqueId());

    newTempDir("testDir");
    assertEquals(expectedTempRootId + "testDir/",
        delegate.newDocId(tempRoot.resolve("testDir")).getUniqueId());

    newTempFile("test");
    assertEquals(expectedTempRootId + "test",
        delegate.newDocId(tempRoot.resolve("test")).getUniqueId());
  }

  private String getTempRootAsUncPath() throws IOException {
    String tempPath = temp.getRoot().getCanonicalPath();
    if (tempPath.length() > 2 && tempPath.charAt(1) == ':') {
      String uncPath = "\\\\localhost\\" + tempPath.substring(0, 1) + "$"
          + tempPath.substring(2);
      try {
        // Now verify we have access to the local administrative share.
        if (new File(uncPath).list() != null) {
          return uncPath;
        }
      } catch (SecurityException e) {
        // Cannot access local administrative share.
      }
    }
    return null;
  }

  @Test
  public void testStartMonitorBadPath() throws Exception {
    Path file = newTempFile("test.txt");
    thrown.expect(IOException.class);
    delegate.startMonitorPath(file, queue);
  }

  @Test
  public void testStartStopMonitor() throws Exception {
    delegate.startMonitorPath(tempRoot, queue);
    delegate.stopMonitorPath();
  }

  @Test
  public void testMonitorAddFile() throws Exception {
    // These shouldn't show up as new or modified.
    newTempDir("existingDir");
    newTempFile("existingFile");
    delegate.startMonitorPath(tempRoot, queue);
    Path file = newTempFile("test.txt");
    // Adding a file shows up as a change to its parent.
    checkForChanges(Collections.singleton(tempRoot));
  }

  @Test
  public void testMonitorDeleteFile() throws Exception {
    Path file = newTempFile("test.txt");
    delegate.startMonitorPath(tempRoot, queue);
    Files.delete(file);
    // Deleting a file shows up as a change to itself and its parent.
    checkForChanges(Sets.newHashSet(tempRoot, file));
  }

  @Test
  public void testMonitorRenameFile() throws Exception {
    Path file = newTempFile("test.txt");
    Path newFile = file.resolveSibling("newName.txt");
    delegate.startMonitorPath(tempRoot, queue);
    Files.move(file, newFile, StandardCopyOption.ATOMIC_MOVE);
    // Renaming a file shows up as a change to its old name, its new name,
    // and its parent.
    checkForChanges(Sets.newHashSet(tempRoot, file, newFile));
  }

  @Test
  public void testMonitorMoveAccrossDirs() throws Exception {
    Path dir1 = newTempDir("dir1");
    Path dir2 = newTempDir("dir2");
    Path file1 = newTempFile(dir1, "test.txt");
    Path file2 = dir2.resolve(file1.getFileName());
    delegate.startMonitorPath(tempRoot, queue);
    Files.move(file1, file2);
    // Moving a file shows up as a change to its old name, its new name,
    // its old parent, and its new parent.
    checkForChanges(Sets.newHashSet(file1, file2, dir1, dir2));
  }

  @Test
  public void testMonitorModifyFile() throws Exception {
    Path file = newTempFile("test.txt");
    delegate.startMonitorPath(tempRoot, queue);
    Files.write(file, "Hello World".getBytes("UTF-8"));
    // Modifying a file shows up as a change to that file.
    checkForChanges(Collections.singleton(file));
  }

  @Test
  public void testMonitorModifyFileAttributes() throws Exception {
    Path file = newTempFile("test.txt");
    FileTime lastModified = Files.getLastModifiedTime(file);
    delegate.startMonitorPath(tempRoot, queue);
    Files.setLastModifiedTime(file, 
        FileTime.fromMillis(lastModified.toMillis() + 10000L));
    // Modifying a file shows up as a change to that file.
    checkForChanges(Collections.singleton(file));
  }

  @Test
  public void testMonitorRenameDir() throws Exception {
    Path dir = newTempDir("dir1");
    Path newDir = dir.resolveSibling("newName.dir");
    delegate.startMonitorPath(tempRoot, queue);
    Files.move(dir, newDir, StandardCopyOption.ATOMIC_MOVE);
    // Renaming a directory shows up as a change to its old name, its new name,
    // and its parent.
    checkForChanges(Sets.newHashSet(tempRoot, dir));
  }

  @Test
  public void testMonitorMoveDir() throws Exception {
    Path dir1 = newTempDir("dir1");
    Path dir2 = newTempDir("dir2");
    Path dir1dir2 = dir1.resolve(dir2.getFileName());
    delegate.startMonitorPath(tempRoot, queue);
    Files.move(dir2, dir1dir2);
    // Moving a file shows up as a change to its old name, its new name,
    // its old parent, and its new parent.
    checkForChanges(Sets.newHashSet(tempRoot, dir1, dir2));
  }

  @Test
  public void testMonitorChangesInSubDirs() throws Exception {
    Path dir = newTempDir("testDir");
    Path file = newTempFile(dir, "test.txt");
    delegate.startMonitorPath(tempRoot, queue);
    Files.write(file, "Hello World".getBytes("UTF-8"));
    // Modifying a file shows up as a change to that file.
    checkForChanges(Collections.singleton(file));
  }

  private void checkForChanges(Set<Path> expected) throws Exception {
    // Collect up the changes.  Adapted from BlockingQueueBatcher.take(),
    // but without infinite initial wait.
    Set<Path> changes = Sets.newHashSet();
    int maxBatchSize = expected.size();
    long maxLatencyMillis = 10000;
    long currentTime = System.currentTimeMillis();
    long stopBatchTime = currentTime + maxLatencyMillis;

    while (currentTime < stopBatchTime && changes.size() < maxBatchSize) {
      // Block until an item is in the queue or the batch timeout expires.
      Path path =
          queue.poll(stopBatchTime - currentTime, TimeUnit.MILLISECONDS);
      if (path == null) {
        // Timeout occurred.
        break;
      }
      changes.add(path);
      queue.drainTo(changes);
      currentTime = System.currentTimeMillis();
    }

    // Now verify that the changes we got were the ones that were expected.
    assertEquals(expected, changes);
  }
}
