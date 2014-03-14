// Copyright 2014 Google Inc.
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

import static org.junit.Assert.*;

import com.google.common.base.Charsets;
import com.google.common.io.CharStreams;

import org.junit.*;
import org.junit.rules.ExpectedException;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.nio.file.DirectoryStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Iterator;

/**
 * Test cases for {@link MockFile}.
 */
public class MockFileTest {

  private static final FileTime createTime = FileTime.fromMillis(20000);
  private static final FileTime modifyTime = FileTime.fromMillis(30000);
  private static final FileTime accessTime = FileTime.fromMillis(40000);

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  @Test
  public void testConstructorNullName() throws Exception {
    thrown.expect(NullPointerException.class);
    new MockFile(null);
  }

  /** Test constructor for regular files. */
  @Test
  public void testFileConstructor() throws Exception {
    MockFile f = new MockFile("test");
    checkDefaultConfig(f, "test", false);
    assertEquals("Contents of test", readContents(f));
    assertEquals("text/plain", f.getContentType());
  }

  /** Test constructor for directories . */
  @Test
  public void testDirectoryConstructor() throws Exception {
    MockFile f = new MockFile("test", true);
    checkDefaultConfig(f, "test", true);
    DirectoryStream<Path> ds = f.newDirectoryStream();
    assertNotNull(ds);
    assertFalse(ds.iterator().hasNext());
    ds.close();
  }

  /**
   * Verifies some of the default file attributes (no explicit setters called).
   */
  private void checkDefaultConfig(MockFile file, String name, boolean isDir)
      throws Exception {
    assertEquals(name, file.getName());
    assertEquals(isDir, file.isDirectory());
    assertEquals(!isDir, file.isRegularFile());
    assertFalse(file.isHidden());
    assertNull(file.getParent());
    assertEquals(MockFile.DEFAULT_FILETIME, file.getCreationTime());
    assertEquals(MockFile.DEFAULT_FILETIME, file.getLastModifiedTime());
    assertEquals(MockFile.DEFAULT_FILETIME, file.getLastAccessTime());
  }

  private String readContents(MockFile file) throws IOException {
    return CharStreams.toString(
        new InputStreamReader(file.newInputStream(), Charsets.UTF_8));
  }

  @Test
  public void testSetName() throws Exception {
    assertEquals("foo", new MockFile("test").setName("foo").getName());
  }

  @Test
  public void testSetIsRegularFile() throws Exception {
    MockFile f = new MockFile("test").setIsRegularFile(false);
    assertFalse(f.isRegularFile());
    assertFalse(f.isDirectory());

    f.setIsRegularFile(true);
    assertTrue(f.isRegularFile());
    assertFalse(f.isDirectory());
  }

  @Test
  public void testSetIsHidden() throws Exception {
    MockFile f = new MockFile("test");
    assertFalse(f.isHidden());  // default is false.
    assertTrue(f.setIsHidden(true).isHidden());
    assertFalse(f.setIsHidden(false).isHidden());
  }

  @Test
  public void testSetFileTimes() throws Exception {
    MockFile f = new MockFile("test").setCreationTime(createTime)
        .setLastModifiedTime(modifyTime).setLastAccessTime(accessTime);
    assertEquals(createTime, f.getCreationTime());
    assertEquals(modifyTime, f.getLastModifiedTime());
    assertEquals(accessTime, f.getLastAccessTime());
  }

  @Test
  public void testReadBasicAttributesRegularFile() throws Exception {
    MockFile f = new MockFile("test").setCreationTime(createTime)
        .setLastModifiedTime(modifyTime).setLastAccessTime(accessTime);

    BasicFileAttributes bfa = f.readBasicAttributes();
    assertNotNull(bfa);
    assertSame(f, bfa.fileKey());
    assertEquals(createTime, bfa.creationTime());
    assertEquals(modifyTime, bfa.lastModifiedTime());
    assertEquals(accessTime, bfa.lastAccessTime());
    assertTrue(bfa.isRegularFile());
    assertFalse(bfa.isDirectory());
    assertFalse(bfa.isSymbolicLink());
    assertFalse(bfa.isOther());
    assertEquals(readContents(f).length(), bfa.size());
  }

  @Test
  public void testReadBasicAttributesDirectory() throws Exception {
    MockFile f = new MockFile("test", true).setCreationTime(createTime)
        .setLastModifiedTime(modifyTime).setLastAccessTime(accessTime);

    BasicFileAttributes bfa = f.readBasicAttributes();
    assertNotNull(bfa);
    assertSame(f, bfa.fileKey());
    assertEquals(createTime, bfa.creationTime());
    assertEquals(modifyTime, bfa.lastModifiedTime());
    assertEquals(accessTime, bfa.lastAccessTime());
    assertFalse(bfa.isRegularFile());
    assertTrue(bfa.isDirectory());
    assertFalse(bfa.isSymbolicLink());
    assertFalse(bfa.isOther());
    assertEquals(0L, bfa.size());
  }

  @Test
  public void testReadBasicAttributesSpecialFile() throws Exception {
    // If neither file, nor directory, then it is "special".
    MockFile f = new MockFile("test", false).setIsRegularFile(false);
    BasicFileAttributes bfa = f.readBasicAttributes();
    assertFalse(bfa.isRegularFile());
    assertFalse(bfa.isDirectory());
    assertFalse(bfa.isSymbolicLink());
    assertTrue(bfa.isOther());
    assertEquals(0L, bfa.size());
  }

  @Test
  public void testSetFileContents() throws Exception {
    String expected = "Hello World";
    MockFile f = new MockFile("test.txt").setFileContents(expected);
    assertEquals(expected, readContents(f));
  }

  @Test
  public void testSetFileContentsBytes() throws Exception {
    String expected = "<html><title>Hello World</title></html>";
    MockFile f = new MockFile("test.html")
        .setFileContents(expected.getBytes(Charsets.UTF_8))
        .setContentType("text/html");
    assertEquals(expected, readContents(f));
    assertEquals("text/html", f.getContentType());
  }

  @Test
  public void testChildren() throws Exception {
    MockFile root = new MockFile("root", true);
    MockFile dir1 = new MockFile("dir1", true);
    MockFile dir2 = new MockFile("dir2", true);
    MockFile test = new MockFile("test.txt");
    root.addChildren(test, dir1, dir2);
    assertNull(root.getParent());
    assertSame(root, dir1.getParent());
    assertSame(root, dir2.getParent());
    assertSame(root, test.getParent());
    checkDirectoryListing(root, dir1, dir2, test);

    // Test getChild().
    assertSame(dir1, root.getChild("dir1"));
    assertSame(dir2, root.getChild("dir2"));
    assertSame(test, root.getChild("test.txt"));

    // Add another file.
    MockFile newer = new MockFile("newer.txt");
    root.addChildren(newer);
    checkDirectoryListing(root, dir1, dir2, newer, test);
  }

  private void checkDirectoryListing(MockFile parent, MockFile... children)
      throws IOException {
    DirectoryStream<Path> ds = parent.newDirectoryStream();
    assertNotNull(ds);
    Iterator<Path> iter = ds.iterator();
    assertNotNull(iter);
    for (MockFile child : children) {
      assertEquals(child.getName(), iter.next().getFileName().toString());
    }
    assertFalse(iter.hasNext());
    ds.close();
  }

  @Test
  public void testGetPath() throws Exception {
    MockFile root = new MockFile("root", true);
    MockFile dir1 = new MockFile("dir1", true);
    MockFile test = new MockFile("test.txt");
    MockFile test1 = new MockFile("test.txt");
    root.addChildren(test, dir1);
    dir1.addChildren(test1);
    assertEquals("root", root.getPath());
    assertEquals("root/dir1", dir1.getPath());
    assertEquals("root/test.txt", test.getPath());
    assertEquals("root/dir1/test.txt", test1.getPath());
  }

  @Test
  public void testGetChildNullName() throws Exception {
    thrown.expect(NullPointerException.class);
    new MockFile("root", true).getChild(null);
  }

  @Test
  public void testGetChildNotFound() throws Exception {
    thrown.expect(FileNotFoundException.class);
    new MockFile("root", true).getChild("nonExistent");
  }

  @Test
  public void testGetDfsUncActiveStorageUnc() throws Exception {
    MockFile root = new MockFile("root", true);
    assertNull(root.getDfsUncActiveStorageUnc());
    Path uncPath = Paths.get("\\\\server\\share");
    root.setDfsUncActiveStorageUnc(uncPath);
    assertEquals(uncPath, root.getDfsUncActiveStorageUnc());
  }

  @Test
  public void testGetDfsShareAclView() throws Exception {
    MockFile root = new MockFile("root", true);
    assertNull(root.getDfsShareAclView());
    root.setDfsShareAclView(MockFile.FULL_ACCESS_ACLVIEW);
    assertEquals(MockFile.FULL_ACCESS_ACLVIEW, root.getDfsShareAclView());
  }

  @Test
  public void testDefaultRootAclViews() throws Exception {
    MockFile root = new MockFile("root", true);
    assertEquals(MockFile.FULL_ACCESS_ACLVIEW, root.getShareAclView());
    assertEquals(MockFile.FULL_ACCESS_ACLVIEW, root.getAclView());
    assertEquals(MockFile.EMPTY_ACLVIEW, root.getInheritedAclView());
  }

  @Test
  public void testDefaultNonRootAclViews() throws Exception {
    MockFile root = new MockFile("root", true);
    MockFile dir1 = new MockFile("dir1", true);
    MockFile foo = new MockFile("foo");
    MockFile bar = new MockFile("bar");
    root.addChildren(dir1, foo);
    dir1.addChildren(bar);
    assertEquals(MockFile.EMPTY_ACLVIEW, dir1.getAclView());
    assertEquals(MockFile.FULL_ACCESS_ACLVIEW, dir1.getInheritedAclView());
    assertEquals(MockFile.EMPTY_ACLVIEW, foo.getAclView());
    assertEquals(MockFile.FULL_ACCESS_ACLVIEW, foo.getInheritedAclView());
    assertEquals(MockFile.EMPTY_ACLVIEW, bar.getAclView());
    assertEquals(MockFile.FULL_ACCESS_ACLVIEW, bar.getInheritedAclView());
  }

  @Test
  public void testSetAclViews() throws Exception {
    MockFile root = new MockFile("root", true);
    MockFile foo = new MockFile("foo");
    root.addChildren(foo);
    assertEquals(MockFile.EMPTY_ACLVIEW, foo.getAclView());
    assertEquals(MockFile.FULL_ACCESS_ACLVIEW, foo.getInheritedAclView());

    foo.setAclView(MockFile.FULL_ACCESS_ACLVIEW);
    foo.setInheritedAclView(MockFile.EMPTY_ACLVIEW);
    assertEquals(MockFile.FULL_ACCESS_ACLVIEW, foo.getAclView());
    assertEquals(MockFile.EMPTY_ACLVIEW, foo.getInheritedAclView());
  }
}
