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

import static com.google.enterprise.adaptor.fs.AclView.user;
import static com.google.enterprise.adaptor.fs.AclView.group;
import static com.google.enterprise.adaptor.fs.AclView.GenericPermission.*;

import static org.junit.Assert.*;

import static java.nio.file.attribute.AclEntryFlag.*;
import static java.nio.file.attribute.AclEntryPermission.*;
import static java.nio.file.attribute.AclEntryType.*;

import com.google.common.collect.ImmutableSet;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Sets;
import com.google.enterprise.adaptor.Acl;
import com.google.enterprise.adaptor.Acl.InheritanceType;
import com.google.enterprise.adaptor.AdaptorContext;
import com.google.enterprise.adaptor.Config;
import com.google.enterprise.adaptor.DocId;
import com.google.enterprise.adaptor.DocIdPusher.Record;
import com.google.enterprise.adaptor.GroupPrincipal;
import com.google.enterprise.adaptor.InvalidConfigurationException;
import com.google.enterprise.adaptor.StartupException;
import com.google.enterprise.adaptor.UnsupportedPlatformException;
import com.google.enterprise.adaptor.UserPrincipal;

import org.junit.*;
import org.junit.rules.ExpectedException;

import java.io.File;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.AccessDeniedException;
import java.nio.file.DirectoryStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.FileTime;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.BlockingQueue;

/** Test cases for {@link FsAdaptor}. */
public class FsAdaptorTest {

  static final String ROOT = "/";
  static final Path rootPath = Paths.get(ROOT);
  static final DocId shareAclDocId = new DocId("shareAcl");

  private final Set<String> windowsAccounts = ImmutableSet.of(
      "BUILTIN\\Administrators", "Everyone", "BUILTIN\\Users",
      "BUILTIN\\Guest", "NT AUTHORITY\\INTERACTIVE",
      "NT AUTHORITY\\Authenticated Users");
  private final String builtinPrefix = "BUILTIN\\";
  private final String namespace = "Default";

  private AdaptorContext context = new MockAdaptorContext();
  private AccumulatingDocIdPusher pusher =
      (AccumulatingDocIdPusher) context.getDocIdPusher();
  private Config config = context.getConfig();
  private MockFile root = new MockFile(ROOT, true);
  private MockFileDelegate delegate = new MockFileDelegate(root);
  private FsAdaptor adaptor = new FsAdaptor(delegate);
  private DocId rootDocId;

  @Before
  public void setUp() throws Exception {
    rootDocId = delegate.newDocId(rootPath);
    adaptor.initConfig(config);
    config.overrideKey("filesystemadaptor.src", root.getPath());
    config.overrideKey("adaptor.incrementalPollPeriodSecs", "0");
  }

  @After
  public void tearDown() throws Exception {
    adaptor.destroy();
  }

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  private Path getPath(String path) {
    return rootPath.resolve(path);
  }

  private DocId getDocId(String path) throws IOException {
    return delegate.newDocId(getPath(path));
  }

  @Test
  public void testAdaptorStartupShutdown() throws Exception {
    // Construction of Adaptor happened in setUp(), and
    // destruction will happen in tearDown(), so the only
    // thing left is to init the context.
    adaptor.init(context);
  }

  @Test
  public void testAdaptorInitNoSourcePath() throws Exception {
    config.overrideKey("filesystemadaptor.src", "");
    thrown.expect(InvalidConfigurationException.class);
    adaptor.init(context);
  }

  @Test
  public void testAdaptorInitNonRootSourcePath() throws Exception {
    root.addChildren(new MockFile("subdir", true));
    config.overrideKey("filesystemadaptor.src", getPath("subdir").toString());
    thrown.expect(InvalidConfigurationException.class);
    adaptor.init(context);
  }

  @Test
  public void testAdaptorInitDfsLink() throws Exception {
    root.setDfsActiveStorage(Paths.get("\\\\dfshost\\share"));
    root.setDfsShareAclView(MockFile.FULL_ACCESS_ACLVIEW);
    adaptor.init(context);
  }

  @Test
  public void testAdaptorInitDfsLinkNoActiveStorage() throws Exception {
    root.setIsDfsLink(true);
    root.setDfsShareAclView(MockFile.FULL_ACCESS_ACLVIEW);
    thrown.expect(IOException.class);
    adaptor.init(context);
  }

  @Test
  public void testAdaptorInitDfsRoot() throws Exception {
    root.setIsDfsRoot(true);
    thrown.expect(InvalidConfigurationException.class);
    adaptor.init(context);
  }

  @Test
  public void testAdaptorInitSupportedWindowsAccounts() throws Exception {
    String accounts = "Everyone, BUILTIN\\Users, NT AUTH\\New Users";
    Set<String> expected =
        ImmutableSet.of("Everyone", "BUILTIN\\Users", "NT AUTH\\New Users");
    config.overrideKey("filesystemadaptor.supportedAccounts", accounts);
    adaptor.init(context);
    assertEquals(expected, adaptor.getSupportedWindowsAccounts());
  }

  @Test
  public void testAdaptorInitBuiltinGroupPrefix() throws Exception {
    String expected = "TestPrefix";
    config.overrideKey("filesystemadaptor.builtinGroupPrefix", expected);
    adaptor.init(context);
    assertEquals(expected, adaptor.getBuiltinPrefix());
  }

  @Test
  public void testAdaptorInitNamespace() throws Exception {
    String expected = "TestNamespace";
    config.overrideKey("adaptor.namespace", expected);
    adaptor.init(context);
    assertEquals(expected, adaptor.getNamespace());
  }

  @Test
  public void testAdaptorInitNoCrawlHiddenRoot() throws Exception {
    root.setIsHidden(true);
    thrown.expect(InvalidConfigurationException.class);
    adaptor.init(context);
  }

  @Test
  public void testAdaptorInitCrawlHiddenRoot() throws Exception {
    root.setIsHidden(true);
    config.overrideKey("filesystemadaptor.crawlHiddenFiles", "true");
    adaptor.init(context);
  }

  @Test
  public void testGetFolderName() throws Exception {
    assertEquals("share", adaptor.getFileName(Paths.get("\\\\host/share/")));
    assertEquals("folder2",
        adaptor.getFileName(Paths.get("C:/folder1/folder2/")));
    assertEquals("folder2",
        adaptor.getFileName(Paths.get("/folder1/folder2/")));
    assertEquals("share", adaptor.getFileName(Paths.get("\\\\host/share")));
    assertEquals("folder1",
        adaptor.getFileName(Paths.get("/folder1")));
    assertEquals(File.separator,  // Windows flips the '/' to '\'.
        adaptor.getFileName(Paths.get("/")));
    assertEquals("C:\\",
        adaptor.getFileName(Paths.get("C:\\")));
  }

  @Test
  public void testIsFileOrFolder() throws Exception {
    root.addChildren(new MockFile("foo"), new MockFile("bar", true),
                     new MockFile("link").setIsRegularFile(false));
    assertTrue(adaptor.isFileOrFolder(rootPath));
    assertTrue(adaptor.isFileOrFolder(getPath("foo")));
    assertTrue(adaptor.isFileOrFolder(getPath("bar")));
    assertFalse(adaptor.isFileOrFolder(getPath("link")));
  }

  @Test
  public void testIsVisibleDescendantOfRoot() throws Exception {
    adaptor.init(context);
    root.addChildren(new MockFile("foo"),
        new MockFile("hidden.txt").setIsHidden(true),
        new MockFile("dir1", true).addChildren(new MockFile("bar"),
            new MockFile("hidden.pdf").setIsHidden(true)),
        new MockFile("hidden.dir", true).setIsHidden(true).addChildren(
            new MockFile("baz")));
    assertTrue(adaptor.isVisibleDescendantOfRoot(rootPath));
    assertTrue(adaptor.isVisibleDescendantOfRoot(getPath("foo")));
    assertTrue(adaptor.isVisibleDescendantOfRoot(getPath("dir1")));
    assertTrue(adaptor.isVisibleDescendantOfRoot(getPath("dir1/bar")));
    assertFalse(adaptor.isVisibleDescendantOfRoot(getPath("hidden.txt")));
    assertFalse(adaptor.isVisibleDescendantOfRoot(getPath("dir1/hidden.pdf")));
    assertFalse(adaptor.isVisibleDescendantOfRoot(getPath("hidden.dir")));
    assertFalse(adaptor.isVisibleDescendantOfRoot(getPath("hidden.dir/baz")));
    assertFalse(adaptor.isVisibleDescendantOfRoot(null));
  }

  @Test
  public void testIsVisibleDescendantOfRootCrawlHiddenTrue() throws Exception {
    config.overrideKey("filesystemadaptor.crawlHiddenFiles", "true");
    adaptor.init(context);
    root.addChildren(new MockFile("foo"),
        new MockFile("hidden.txt").setIsHidden(true),
        new MockFile("dir1", true).addChildren(new MockFile("bar"),
            new MockFile("hidden.pdf").setIsHidden(true)),
        new MockFile("hidden.dir", true).setIsHidden(true).addChildren(
            new MockFile("baz")));
    assertTrue(adaptor.isVisibleDescendantOfRoot(rootPath));
    assertTrue(adaptor.isVisibleDescendantOfRoot(getPath("foo")));
    assertTrue(adaptor.isVisibleDescendantOfRoot(getPath("dir1")));
    assertTrue(adaptor.isVisibleDescendantOfRoot(getPath("dir1/bar")));
    assertTrue(adaptor.isVisibleDescendantOfRoot(getPath("hidden.txt")));
    assertTrue(adaptor.isVisibleDescendantOfRoot(getPath("dir1/hidden.pdf")));
    assertTrue(adaptor.isVisibleDescendantOfRoot(getPath("hidden.dir")));
    assertTrue(adaptor.isVisibleDescendantOfRoot(getPath("hidden.dir/baz")));
  }

  @Test
  public void testGetDocIds() throws Exception {
    adaptor.init(context);
    adaptor.getDocIds(pusher);

    // We should just push the root docid.
    List<Record> records = pusher.getRecords();
    assertEquals(1, records.size());
    assertEquals(delegate.newDocId(rootPath), records.get(0).getDocId());

    // We should have pushed an acl for the share.
    List<Map<DocId, Acl>> namedResources = pusher.getNamedResources();
    Acl expected = new Acl.Builder().setEverythingCaseInsensitive()
        .setPermitGroups(Collections.singleton(new GroupPrincipal("Everyone")))
        .setInheritanceType(InheritanceType.AND_BOTH_PERMIT).build();
    assertEquals(1, namedResources.size());
    assertEquals(1, namedResources.get(0).size());
    assertEquals(expected, namedResources.get(0).get(shareAclDocId));
  }

  @Test
  public void testGetDocIdsDfs() throws Exception {
    Path uncPath = Paths.get("\\\\dfshost\\share");
    root.setDfsActiveStorage(uncPath);
    root.setDfsShareAclView(MockFile.FULL_ACCESS_ACLVIEW);
    adaptor.init(context);
    adaptor.getDocIds(pusher);

    // We should just push the root docid.
    List<Record> records = pusher.getRecords();
    assertEquals(1, records.size());
    assertEquals(delegate.newDocId(rootPath), records.get(0).getDocId());

    // We should have pushed acls for the share and the dfsShare.
    List<Map<DocId, Acl>> namedResources = pusher.getNamedResources();
    DocId dfsShareAcl = new DocId("dfsShareAcl");
    Acl expectedDfsShareAcl = new Acl.Builder().setEverythingCaseInsensitive()
        .setPermitGroups(Collections.singleton(new GroupPrincipal("Everyone")))
        .setInheritanceType(InheritanceType.AND_BOTH_PERMIT).build();
    Acl expectedShareAcl = new Acl.Builder(expectedDfsShareAcl)
        .setInheritFrom(dfsShareAcl).build();
    assertEquals(1, namedResources.size());
    Map<DocId, Acl> acls = namedResources.get(0);
    assertEquals(2, acls.size());
    assertEquals(expectedDfsShareAcl, acls.get(dfsShareAcl));
    assertEquals(expectedShareAcl, acls.get(shareAclDocId));
  }

  @Test
  public void testGetDocIdsSkipShareAcl() throws Exception {
    config.overrideKey("filesystemadaptor.skipShareAccessControl", "true");
    adaptor.init(context);
    adaptor.getDocIds(pusher);

    // We should just push the root docid.
    List<Record> records = pusher.getRecords();
    assertEquals(1, records.size());
    assertEquals(delegate.newDocId(rootPath), records.get(0).getDocId());

    // We should have pushed an empty, child-overrides ACL for the share.
    List<Map<DocId, Acl>> namedResources = pusher.getNamedResources();
    Acl expected = new Acl.Builder().setEverythingCaseInsensitive()
        .setInheritanceType(InheritanceType.CHILD_OVERRIDES).build();
    assertEquals(1, namedResources.size());
    assertEquals(1, namedResources.get(0).size());
    assertEquals(expected, namedResources.get(0).get(shareAclDocId));
  }

  @Test
  public void testGetDocIdsDfsSkipShareAcls() throws Exception {
    Path uncPath = Paths.get("\\\\dfshost\\share");
    root.setDfsActiveStorage(uncPath);
    root.setDfsShareAclView(MockFile.FULL_ACCESS_ACLVIEW);
    config.overrideKey("filesystemadaptor.skipShareAccessControl", "true");
    adaptor.init(context);
    adaptor.getDocIds(pusher);

    // We should just push the root docid.
    List<Record> records = pusher.getRecords();
    assertEquals(1, records.size());
    assertEquals(delegate.newDocId(rootPath), records.get(0).getDocId());

    // We should have pushed an empty, child-overrides ACL for the share.
    List<Map<DocId, Acl>> namedResources = pusher.getNamedResources();
    Acl expected = new Acl.Builder().setEverythingCaseInsensitive()
        .setInheritanceType(InheritanceType.CHILD_OVERRIDES).build();
    assertEquals(1, namedResources.size());
    assertEquals(1, namedResources.get(0).size());
    assertEquals(expected, namedResources.get(0).get(shareAclDocId));
  }

  @Test
  public void testGetDocIdsBrokenDfs() throws Exception {
    Path uncPath = Paths.get("\\\\dfshost\\share");
    root.setDfsActiveStorage(uncPath);
    root.setDfsShareAclView(MockFile.FULL_ACCESS_ACLVIEW);
    adaptor.init(context);

    // Now make the active storage disappear.
    root.setDfsActiveStorage(null);
    thrown.expect(IOException.class);
    adaptor.getDocIds(pusher);
  }

  @Test
  public void testGetDocContentInvalidPath() throws Exception {
    adaptor.init(context);
    MockResponse response = new MockResponse();
    adaptor.getDocContent(new MockRequest(new DocId("")), response);
    assertTrue(response.notFound);
  }

  @Test
  public void testGetDocContentUnsupportedPath() throws Exception {
    root.addChildren(new MockFile("unsupported").setIsRegularFile(false));
    adaptor.init(context);
    MockResponse response = new MockResponse();
    adaptor.getDocContent(new MockRequest(getDocId("unsupported")), response);
    assertTrue(response.notFound);
  }

  @Test
  public void testGetDocContentBadDocId() throws Exception {
    root.addChildren(new MockFile("badfile"));
    adaptor.init(context);
    MockResponse response = new MockResponse();
    // The requested DocId is missing the root component of the path.
    adaptor.getDocContent(new MockRequest(new DocId("badfile")), response);
    assertTrue(response.notFound);
  }

  @Test
  public void testGetDocContentFileNotFound() throws Exception {
    adaptor.init(context);
    MockResponse response = new MockResponse();
    // The requested DocId is missing the root component of the path.
    adaptor.getDocContent(new MockRequest(getDocId("non-existent")), response);
    assertTrue(response.notFound);
  }

  @Test
  public void testGetDocContentHiddenFile() throws Exception {
    root.addChildren(new MockFile("hidden.txt").setIsHidden(true));
    adaptor.init(context);
    MockResponse response = new MockResponse();
    adaptor.getDocContent(new MockRequest(getDocId("hidden.txt")), response);
    assertTrue(response.notFound);
  }

  @Test
  public void testGetDocContentHiddenDirectory() throws Exception {
    root.addChildren(new MockFile("hidden.dir", true).setIsHidden(true));
    adaptor.init(context);
    MockResponse response = new MockResponse();
    adaptor.getDocContent(new MockRequest(getDocId("hidden.dir")), response);
    assertTrue(response.notFound);
  }

  @Test
  public void testGetDocContentHiddenFileCrawlHiddenTrue() throws Exception {
    root.addChildren(new MockFile("hidden.txt").setIsHidden(true));
    config.overrideKey("filesystemadaptor.crawlHiddenFiles", "true");
    adaptor.init(context);
    MockResponse response = new MockResponse();
    adaptor.getDocContent(new MockRequest(getDocId("hidden.txt")), response);
    assertFalse(response.notFound);
  }

  @Test
  public void testGetDocContentHiddenDirectoryCrawlHiddenTrue()
      throws Exception {
    root.addChildren(new MockFile("hidden.dir", true).setIsHidden(true));
    config.overrideKey("filesystemadaptor.crawlHiddenFiles", "true");
    adaptor.init(context);
    MockResponse response = new MockResponse();
    adaptor.getDocContent(new MockRequest(getDocId("hidden.dir")), response);
    assertFalse(response.notFound);
  }

  @Test
  public void testGetDocContentRegularFile() throws Exception {
    String fname = "test.html";
    Date modifyDate = new Date(30000);
    FileTime modifyTime = FileTime.fromMillis(modifyDate.getTime());
    String content = "<html><title>Hello World</title></html>";
    root.addChildren(new MockFile(fname).setLastModifiedTime(modifyTime)
        .setFileContents(content).setContentType("text/html"));
    adaptor.init(context);

    MockResponse response = new MockResponse();
    adaptor.getDocContent(new MockRequest(getDocId(fname)), response);
    assertFalse(response.notFound);
    assertEquals(modifyDate, response.lastModified);
    assertEquals(getPath(fname).toUri(), response.displayUrl);
    assertEquals("text/html", response.contentType);
    assertEquals(content, response.content.toString("UTF-8"));
    // TODO: check metadata.
    assertNotNull(response.metadata.get("Creation Time"));
    // ACL checked in other tests.
  }

  @Test
  public void testGetDocContentRootAcl() throws Exception {
    Acl expectedAcl = new Acl.Builder().setEverythingCaseInsensitive()
        .setPermitGroups(Collections.singleton(new GroupPrincipal("Everyone")))
        .setInheritFrom(shareAclDocId)
        .setInheritanceType(InheritanceType.CHILD_OVERRIDES).build();
    adaptor.init(context);
    MockRequest request = new MockRequest(delegate.newDocId(rootPath));
    MockResponse response = new MockResponse();
    adaptor.getDocContent(request, response);
    assertEquals(expectedAcl, response.acl);
  }

  @Test
  public void testGetDocContentEmptyAcl() throws Exception {
    Acl expectedAcl = new Acl.Builder().setEverythingCaseInsensitive()
        .setInheritFrom(rootDocId, "childFilesAcl")
        .setInheritanceType(InheritanceType.LEAF_NODE).build();
    testFileAcl(MockFile.EMPTY_ACLVIEW, null, expectedAcl);
  }

  @Test
  public void testGetDocContentDirectAcl() throws Exception {
    AclFileAttributeView aclView = new AclView((user("joe")
        .type(ALLOW).perms(GENERIC_READ).build()));
    Acl expectedAcl = new Acl.Builder().setEverythingCaseInsensitive()
        .setPermitUsers(Collections.singleton(new UserPrincipal("joe")))
        .setInheritFrom(rootDocId, "childFilesAcl")
        .setInheritanceType(InheritanceType.LEAF_NODE).build();
    testFileAcl(aclView, null, expectedAcl);
  }

  @Test
  public void testGetDocContentNoInheritAcl() throws Exception {
    AclFileAttributeView aclView = new AclView((user("joe")
        .type(ALLOW).perms(GENERIC_READ).build()));
    // Should inherit from the share, not the parent.
    Acl expectedAcl = new Acl.Builder().setEverythingCaseInsensitive()
        .setPermitUsers(Collections.singleton(new UserPrincipal("joe")))
        .setInheritFrom(shareAclDocId)
        .setInheritanceType(InheritanceType.LEAF_NODE).build();
    testFileAcl(aclView, MockFile.EMPTY_ACLVIEW, expectedAcl);
  }

  private void testFileAcl(AclFileAttributeView aclView,
      AclFileAttributeView inheritAclView, Acl expectedAcl) throws Exception {
    String fname = "acltest";
    root.addChildren(new MockFile(fname).setAclView(aclView)
                     .setInheritedAclView(inheritAclView));
    adaptor.init(context);
    MockResponse response = new MockResponse();
    adaptor.getDocContent(new MockRequest(getDocId(fname)), response);
    assertEquals(expectedAcl, response.acl);
  }

  /** Test that LastAccessTime is restored after reading the file. */
  @Test
  public void testPreserveFileLastAccessTime() throws Exception {
    testPreserveFileLastAccessTime(new MockFile("test") {
        @Override
        InputStream newInputStream() throws IOException {
          setLastAccessTime(FileTime.fromMillis(
              getLastAccessTime().toMillis() + 1000));
          return super.newInputStream();
        }
      });
  }

  /** Test LastAccessTime is restored even if exception opening the file. */
  @Test
  public void testPreserveFileLastAccessTimeException1() throws Exception {
    thrown.expect(IOException.class);
    testPreserveFileLastAccessTime(new MockFile("test") {
        @Override
        InputStream newInputStream() throws IOException {
          setLastAccessTime(FileTime.fromMillis(
              getLastAccessTime().toMillis() + 1000));
          throw new IOException("newInputStream");
        }
      });
  }

  /** Test LastAccessTime is restored even if exception reading the file. */
  @Test
  public void testPreserveFileLastAccessTimeException2() throws Exception {
    thrown.expect(IOException.class);
    testPreserveFileLastAccessTime(new MockFile("test") {
        @Override
        InputStream newInputStream() throws IOException {
          setLastAccessTime(FileTime.fromMillis(
              getLastAccessTime().toMillis() + 1000));
          return new FilterInputStream(super.newInputStream()) {
              @Override
              public int read(byte[] b, int off, int len) throws IOException {
                throw new IOException("read");
              }
          };
        }
      });
  }

  /** Test LastAccessTime is restored even if exception closing the file. */
  @Test
  public void testPreserveFileLastAccessTimeException3() throws Exception {
    thrown.expect(IOException.class);
    testPreserveFileLastAccessTime(new MockFile("test") {
        @Override
        InputStream newInputStream() throws IOException {
          setLastAccessTime(FileTime.fromMillis(
              getLastAccessTime().toMillis() + 1000));
          return new FilterInputStream(super.newInputStream()) {
              @Override
              public void close() throws IOException {
                throw new IOException("close");
              }
          };
        }
      });
  }

  /** Test that failure to restore LastAccessTime is not fatal. */
  @Test
  public void testPreserveFileLastAccessTimeException4() throws Exception {
    testNoPreserveFileLastAccessTime(new MockFile("test") {
        @Override
        InputStream newInputStream() throws IOException {
          setLastAccessTime(FileTime.fromMillis(
              getLastAccessTime().toMillis() + 1000));
          return super.newInputStream();
        }
        @Override
        MockFile setLastAccessTime(FileTime accessTime) throws IOException {
          if (MockFile.DEFAULT_FILETIME.equals(getLastAccessTime())) {
            // Let the above setting from newInputStream go through.
            return super.setLastAccessTime(accessTime);
          } else {
            // But fail the attempt to restore from FsAdaptor.
            throw new IOException("Restore LastAccessTime");
          }
        }
      });
  }

  private void testPreserveFileLastAccessTime(MockFile file) throws Exception {
    testFileLastAccessTime(file, true);
  }

  private void testNoPreserveFileLastAccessTime(MockFile file)
      throws Exception {
    testFileLastAccessTime(file, false);
  }

  private void testFileLastAccessTime(MockFile file, boolean isPreserved)
      throws Exception {
    String contents = "Test contents";
    file.setFileContents(contents);
    root.addChildren(file);
    adaptor.init(context);
    MockResponse response = new MockResponse();
    FileTime lastAccess = file.getLastAccessTime();
    adaptor.getDocContent(new MockRequest(getDocId(file.getName())), response);
    // Verify we indeed accessed the file
    assertEquals(contents, response.content.toString("UTF-8"));
    if (isPreserved) {
      assertEquals(lastAccess, file.getLastAccessTime());
    } else {
      assertFalse(lastAccess.equals(file.getLastAccessTime()));
    }
  }

  @Test
  public void testGetDocContentRoot() throws Exception {
    testGetDocContentDirectory(rootPath, rootPath.toString());
    // ACLs checked in other tests.
  }

  @Test
  public void testGetDocContentDirectory() throws Exception {
    String fname = "test.dir";
    root.addChildren(new MockFile(fname, true));
    testGetDocContentDirectory(getPath(fname), fname);
    // ACLs checked in other tests.
  }

  private void testGetDocContentDirectory(Path path, String label)
      throws Exception {
    MockFile dir = delegate.getFile(path);
    FileTime modifyTime = dir.getLastModifiedTime();
    Date modifyDate = new Date(modifyTime.toMillis());
    dir.addChildren(new MockFile("test.txt"), new MockFile("subdir", true));
    adaptor.init(context);
    MockRequest request = new MockRequest(delegate.newDocId(path));
    MockResponse response = new MockResponse();
    adaptor.getDocContent(request, response);
    assertFalse(response.notFound);
    assertEquals(modifyDate, response.lastModified);
    assertEquals(path.toUri(), response.displayUrl);
    assertEquals("text/html; charset=UTF-8", response.contentType);
    String expectedContent = "<!DOCTYPE html>\n<html><head><title>Folder "
        + label + "</title></head><body><h1>Folder " + label + "</h1>"
        + "<li><a href=\"subdir/\">subdir</a></li>"
        + "<li><a href=\"test.txt\">test.txt</a></li></body></html>";
    assertEquals(expectedContent, response.content.toString("UTF-8"));
    assertNotNull(response.metadata.get("Creation Time"));
  }

  @Test
  public void testGetDocContentDefaultRootAcls() throws Exception {
    Acl expectedAcl = new Acl.Builder().setEverythingCaseInsensitive()
        .setPermitGroups(Collections.singleton(new GroupPrincipal("Everyone")))
        .setInheritanceType(InheritanceType.CHILD_OVERRIDES)
        .setInheritFrom(shareAclDocId).build();
    Map<String, Acl> expectedResources = ImmutableMap.of(
        "allFoldersAcl", expectedAcl,
        "allFilesAcl", expectedAcl,
        "childFoldersAcl", expectedAcl,
        "childFilesAcl", expectedAcl);
    testGetDocContentAcls(rootPath, expectedAcl, expectedResources);
  }

  @Test
  public void testGetDocContentInheritOnlyRootAcls() throws Exception {
    AclFileAttributeView inheritOnlyAclView = new AclView(
        user("Longfellow Deeds").type(ALLOW).perms(GENERIC_READ)
            .flags(FILE_INHERIT, DIRECTORY_INHERIT, INHERIT_ONLY),
        group("Administrators").type(ALLOW).perms(GENERIC_ALL)
            .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    root.setAclView(inheritOnlyAclView);

    // The root ACL should only include Administrators, not Mr. Deeds.
    Acl expectedAcl = new Acl.Builder().setEverythingCaseInsensitive()
        .setPermitGroups(Collections.singleton(
            new GroupPrincipal("Administrators")))
        .setInheritanceType(InheritanceType.CHILD_OVERRIDES)
        .setInheritFrom(shareAclDocId).build();
    // But the childrens' inherited ACLs should include Mr. Deeds
    Acl expectedInheritableAcl = new Acl.Builder(expectedAcl)
        .setPermitUsers(Collections.singleton(
            new UserPrincipal("Longfellow Deeds")))
        .build();
    Map<String, Acl> expectedResources = ImmutableMap.of(
        "allFoldersAcl", expectedInheritableAcl,
        "allFilesAcl", expectedInheritableAcl,
        "childFoldersAcl", expectedInheritableAcl,
        "childFilesAcl", expectedInheritableAcl);
    testGetDocContentAcls(rootPath, expectedAcl, expectedResources);
  }

  @Test
  public void testGetDocContentNoPropagateRootAcls() throws Exception {
    AclFileAttributeView noPropagateAclView = new AclView(
        user("Barren von Dink").type(ALLOW).perms(GENERIC_READ)
            .flags(FILE_INHERIT, DIRECTORY_INHERIT, NO_PROPAGATE_INHERIT),
        group("Administrators").type(ALLOW).perms(GENERIC_ALL)
            .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    root.setAclView(noPropagateAclView);

    // The root ACL should include both Administrators and the Barren.
    Acl expectedAcl = new Acl.Builder().setEverythingCaseInsensitive()
        .setPermitUsers(Collections.singleton(
            new UserPrincipal("Barren von Dink")))
        .setPermitGroups(Collections.singleton(
            new GroupPrincipal("Administrators")))
        .setInheritanceType(InheritanceType.CHILD_OVERRIDES)
        .setInheritFrom(shareAclDocId).build();
    // The direct childrens' inherited ACLs should include both the
    // Administrators and the Barren, but grandchildren should not
    // inherit the Barren's NO_PROPAGATE permission.
    Acl expectedNonChildAcl = new Acl.Builder(expectedAcl)
        .setPermitUsers(Collections.<UserPrincipal>emptySet()).build();
    Map<String, Acl> expectedResources = ImmutableMap.of(
        "allFoldersAcl", expectedNonChildAcl,
        "allFilesAcl", expectedNonChildAcl,
        "childFoldersAcl", expectedAcl,
        "childFilesAcl", expectedAcl);
    testGetDocContentAcls(rootPath, expectedAcl, expectedResources);
  }

  @Test
  public void testGetDocContentFilesOnlyRootAcls() throws Exception {
    AclFileAttributeView noPropagateAclView = new AclView(
        user("For Your Files Only").type(ALLOW).perms(GENERIC_READ)
            .flags(FILE_INHERIT),
        group("Administrators").type(ALLOW).perms(GENERIC_ALL)
            .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    root.setAclView(noPropagateAclView);

    Acl expectedAcl = new Acl.Builder().setEverythingCaseInsensitive()
        .setPermitUsers(Collections.singleton(
            new UserPrincipal("For Your Files Only")))
        .setPermitGroups(Collections.singleton(
            new GroupPrincipal("Administrators")))
        .setInheritanceType(InheritanceType.CHILD_OVERRIDES)
        .setInheritFrom(shareAclDocId).build();
    // Folders shouldn't include the file-only permissions.
    Acl expectedFolderAcl = new Acl.Builder(expectedAcl)
        .setPermitUsers(Collections.<UserPrincipal>emptySet()).build();
    Map<String, Acl> expectedResources = ImmutableMap.of(
        "allFoldersAcl", expectedFolderAcl,
        "allFilesAcl", expectedAcl,
        "childFoldersAcl", expectedFolderAcl,
        "childFilesAcl", expectedAcl);
    testGetDocContentAcls(rootPath, expectedAcl, expectedResources);
  }

  @Test
  public void testGetDocContentFoldersOnlyRootAcls() throws Exception {
    AclFileAttributeView noPropagateAclView = new AclView(
        user("Fluff 'n Folder").type(ALLOW).perms(GENERIC_READ)
            .flags(DIRECTORY_INHERIT),
        group("Administrators").type(ALLOW).perms(GENERIC_ALL)
            .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    root.setAclView(noPropagateAclView);

    Acl expectedAcl = new Acl.Builder().setEverythingCaseInsensitive()
        .setPermitUsers(Collections.singleton(
            new UserPrincipal("Fluff 'n Folder")))
        .setPermitGroups(Collections.singleton(
            new GroupPrincipal("Administrators")))
        .setInheritanceType(InheritanceType.CHILD_OVERRIDES)
        .setInheritFrom(shareAclDocId).build();
    // Files shouldn't include the folder-only permissions.
    Acl expectedFilesAcl = new Acl.Builder(expectedAcl)
        .setPermitUsers(Collections.<UserPrincipal>emptySet()).build();
    Map<String, Acl> expectedResources = ImmutableMap.of(
        "allFoldersAcl", expectedAcl,
        "allFilesAcl", expectedFilesAcl,
        "childFoldersAcl", expectedAcl,
        "childFilesAcl", expectedFilesAcl);
    testGetDocContentAcls(rootPath, expectedAcl, expectedResources);
  }

  @Test
  public void testGetDocContentDefaultDirectoryAcls() throws Exception {
    String name = "subdir";
    root.addChildren(new MockFile(name, true));
    Acl expectedAcl = new Acl.Builder().setEverythingCaseInsensitive()
        .setInheritanceType(InheritanceType.CHILD_OVERRIDES)
        .setInheritFrom(rootDocId, "childFoldersAcl").build();
    Acl expectedFoldersAcl = new Acl.Builder(expectedAcl)
        .setInheritFrom(rootDocId, "allFoldersAcl").build();
    Acl expectedFilesAcl = new Acl.Builder(expectedAcl)
        .setInheritFrom(rootDocId, "allFilesAcl").build();
    Map<String, Acl> expectedResources = ImmutableMap.of(
        "allFoldersAcl", expectedFoldersAcl,
        "allFilesAcl", expectedFilesAcl,
        "childFoldersAcl", expectedFoldersAcl,
        "childFilesAcl", expectedFilesAcl);
    testGetDocContentAcls(getPath(name), expectedAcl, expectedResources);
  }

  @Test
  public void testGetDocContentNoInheritDirectoryAcls() throws Exception {
    String name = "subdir";
    AclFileAttributeView orphanAclView = new AclView(user("Annie").type(ALLOW)
        .perms(GENERIC_READ).flags(FILE_INHERIT, DIRECTORY_INHERIT));
    root.addChildren(new MockFile(name, true).setAclView(orphanAclView)
        .setInheritedAclView(MockFile.EMPTY_ACLVIEW));
    Acl expectedAcl = new Acl.Builder().setEverythingCaseInsensitive()
        .setPermitUsers(Collections.singleton(new UserPrincipal("Annie")))
        .setInheritanceType(InheritanceType.CHILD_OVERRIDES)
        .setInheritFrom(shareAclDocId).build();
    Map<String, Acl> expectedResources = ImmutableMap.of(
        "allFoldersAcl", expectedAcl,
        "allFilesAcl", expectedAcl,
        "childFoldersAcl", expectedAcl,
        "childFilesAcl", expectedAcl);
    testGetDocContentAcls(getPath(name), expectedAcl, expectedResources);
  }

  @Test
  public void testGetDocContentInheritOnlyDirectoryAcls() throws Exception {
    String name = "subdir";
    AclFileAttributeView inheritOnlyAclView = new AclView(
        user("Longfellow Deeds").type(ALLOW).perms(GENERIC_READ)
            .flags(FILE_INHERIT, DIRECTORY_INHERIT, INHERIT_ONLY),
        group("Administrators").type(ALLOW).perms(GENERIC_ALL)
            .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    root.addChildren(new MockFile(name, true).setAclView(inheritOnlyAclView));

    // The root ACL should only include Administrators, not Mr. Deeds.
    Acl expectedAcl = new Acl.Builder().setEverythingCaseInsensitive()
        .setPermitGroups(Collections.singleton(
            new GroupPrincipal("Administrators")))
        .setInheritanceType(InheritanceType.CHILD_OVERRIDES)
        .setInheritFrom(rootDocId, "childFoldersAcl").build();
    // But the childrens' inherited ACLs should include Mr. Deeds
    Acl expectedFoldersAcl = new Acl.Builder(expectedAcl)
        .setPermitUsers(Collections.singleton(
            new UserPrincipal("Longfellow Deeds")))
        .setInheritFrom(rootDocId, "allFoldersAcl").build();
    Acl expectedFilesAcl = new Acl.Builder(expectedFoldersAcl)
        .setInheritFrom(rootDocId, "allFilesAcl").build();
    Map<String, Acl> expectedResources = ImmutableMap.of(
        "allFoldersAcl", expectedFoldersAcl,
        "allFilesAcl", expectedFilesAcl,
        "childFoldersAcl", expectedFoldersAcl,
        "childFilesAcl", expectedFilesAcl);
    testGetDocContentAcls(getPath(name), expectedAcl, expectedResources);
  }

  @Test
  public void testGetDocContentNoPropagateDirectoryAcls() throws Exception {
    String name = "subdir";
    AclFileAttributeView noPropagateAclView = new AclView(
        user("Barren von Dink").type(ALLOW).perms(GENERIC_READ)
            .flags(FILE_INHERIT, DIRECTORY_INHERIT, NO_PROPAGATE_INHERIT),
        group("Administrators").type(ALLOW).perms(GENERIC_ALL)
            .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    root.addChildren(new MockFile(name, true).setAclView(noPropagateAclView));

    // The root ACL should include both Administrators and the Barren.
    Acl expectedAcl = new Acl.Builder().setEverythingCaseInsensitive()
        .setPermitUsers(Collections.singleton(
            new UserPrincipal("Barren von Dink")))
        .setPermitGroups(Collections.singleton(
            new GroupPrincipal("Administrators")))
        .setInheritanceType(InheritanceType.CHILD_OVERRIDES)
        .setInheritFrom(rootDocId, "childFoldersAcl").build();
    // The direct childrens' inherited ACLs should include both the
    // Administrators and the Barren, but grandchildren should not
    // inherit the Barren's NO_PROPAGATE permission.
    Acl expectedNonChildAcl = new Acl.Builder(expectedAcl)
        .setPermitUsers(Collections.<UserPrincipal>emptySet()).build();
    Map<String, Acl> expectedResources = ImmutableMap.of(
        "allFoldersAcl", new Acl.Builder(expectedNonChildAcl)
            .setInheritFrom(rootDocId, "allFoldersAcl").build(),
        "allFilesAcl", new Acl.Builder(expectedNonChildAcl)
            .setInheritFrom(rootDocId, "allFilesAcl").build(),
        "childFoldersAcl", new Acl.Builder(expectedAcl)
            .setInheritFrom(rootDocId, "allFoldersAcl").build(),
        "childFilesAcl", new Acl.Builder(expectedAcl)
            .setInheritFrom(rootDocId, "allFilesAcl").build());
    testGetDocContentAcls(getPath(name), expectedAcl, expectedResources);
  }

  @Test
  public void testGetDocContentFilesOnlyDirectoryAcls() throws Exception {
    String name = "subdir";
    AclFileAttributeView filesOnlyAclView = new AclView(
        user("For Your Files Only").type(ALLOW).perms(GENERIC_READ)
            .flags(FILE_INHERIT),
        group("Administrators").type(ALLOW).perms(GENERIC_ALL)
            .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    root.addChildren(new MockFile(name, true).setAclView(filesOnlyAclView));

    Acl expectedAcl = new Acl.Builder().setEverythingCaseInsensitive()
        .setPermitUsers(Collections.singleton(
            new UserPrincipal("For Your Files Only")))
        .setPermitGroups(Collections.singleton(
            new GroupPrincipal("Administrators")))
        .setInheritanceType(InheritanceType.CHILD_OVERRIDES)
        .setInheritFrom(rootDocId, "childFoldersAcl").build();
    // Folders shouldn't include the file-only permissions.
    Acl expectedFolderAcl = new Acl.Builder(expectedAcl)
        .setPermitUsers(Collections.<UserPrincipal>emptySet()).build();
    Map<String, Acl> expectedResources = ImmutableMap.of(
        "allFoldersAcl", new Acl.Builder(expectedFolderAcl)
            .setInheritFrom(rootDocId, "allFoldersAcl").build(),
        "allFilesAcl", new Acl.Builder(expectedAcl)
            .setInheritFrom(rootDocId, "allFilesAcl").build(),
        "childFoldersAcl", new Acl.Builder(expectedFolderAcl)
            .setInheritFrom(rootDocId, "allFoldersAcl").build(),
        "childFilesAcl", new Acl.Builder(expectedAcl)
            .setInheritFrom(rootDocId, "allFilesAcl").build());
    testGetDocContentAcls(getPath(name), expectedAcl, expectedResources);
  }

  @Test
  public void testGetDocContentFoldersOnlyDirectoryAcls() throws Exception {
    String name = "subdir";
    AclFileAttributeView foldersOnlyAclView = new AclView(
        user("Fluff 'n Folder").type(ALLOW).perms(GENERIC_READ)
            .flags(DIRECTORY_INHERIT),
        group("Administrators").type(ALLOW).perms(GENERIC_ALL)
            .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    root.addChildren(new MockFile(name, true).setAclView(foldersOnlyAclView));

    Acl expectedAcl = new Acl.Builder().setEverythingCaseInsensitive()
        .setPermitUsers(Collections.singleton(
            new UserPrincipal("Fluff 'n Folder")))
        .setPermitGroups(Collections.singleton(
            new GroupPrincipal("Administrators")))
        .setInheritanceType(InheritanceType.CHILD_OVERRIDES)
        .setInheritFrom(rootDocId, "childFoldersAcl").build();
    // Files shouldn't include the folder-only permissions.
    Acl expectedFilesAcl = new Acl.Builder(expectedAcl)
        .setPermitUsers(Collections.<UserPrincipal>emptySet()).build();
    Map<String, Acl> expectedResources = ImmutableMap.of(
        "allFoldersAcl", new Acl.Builder(expectedAcl)
            .setInheritFrom(rootDocId, "allFoldersAcl").build(),
        "allFilesAcl", new Acl.Builder(expectedFilesAcl)
            .setInheritFrom(rootDocId, "allFilesAcl").build(),
        "childFoldersAcl", new Acl.Builder(expectedAcl)
            .setInheritFrom(rootDocId, "allFoldersAcl").build(),
        "childFilesAcl", new Acl.Builder(expectedFilesAcl)
            .setInheritFrom(rootDocId, "allFilesAcl").build());
    testGetDocContentAcls(getPath(name), expectedAcl, expectedResources);
  }

  private void testGetDocContentAcls(Path path, Acl expectedAcl,
      Map<String, Acl> expectedAclResources) throws Exception {
    adaptor.init(context);
    MockRequest request = new MockRequest(delegate.newDocId(path));
    MockResponse response = new MockResponse();
    adaptor.getDocContent(request, response);
    assertEquals(expectedAcl, response.acl);
    assertEquals(expectedAclResources, response.namedResources);
  }

  @Test
  public void testIncrementalShareAcls() throws Exception {
    adaptor.init(context);

    AclFileAttributeView aclView = new AclView(
        user("joe").type(ALLOW).perms(GENERIC_READ)
        .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    Acl acl =
        newBuilder(aclView).getAcl().setInheritanceType(
        InheritanceType.AND_BOTH_PERMIT).build();
    root.setShareAclView(aclView);

    adaptor.getDocIds(pusher);
    List<Map<DocId, Acl>> namedResources = pusher.getNamedResources();
    assertEquals(1, namedResources.size());
    assertEquals(acl, namedResources.get(0).get(shareAclDocId));

    // Clear the pusher and call getModifiedDocIds. Nothing should be
    // pushed since the share Acl has not changed.
    pusher.reset();
    adaptor.getModifiedDocIds(pusher);
    namedResources = pusher.getNamedResources();
    assertEquals(0, namedResources.size());

    // Change the share Acl and confirm that that the share Acl is pushed.
    aclView = new AclView(user("mary").type(ALLOW).perms(GENERIC_READ)
        .flags(FILE_INHERIT, DIRECTORY_INHERIT));
    acl = newBuilder(aclView).getAcl().setInheritanceType(
        InheritanceType.AND_BOTH_PERMIT).build();
    root.setShareAclView(aclView);

    adaptor.getModifiedDocIds(pusher);
    namedResources = pusher.getNamedResources();
    assertEquals(1, namedResources.size());
    assertEquals(acl, namedResources.get(0).get(shareAclDocId));
  }

  @Test
  public void testInitListRootContentsAccessDenied() throws Exception {
    delegate = new MockFileDelegate(root) {
      @Override
      public DirectoryStream<Path> newDirectoryStream(Path doc)
          throws IOException {
        throw new AccessDeniedException(doc.toString());
      }
    };
    adaptor = new FsAdaptor(delegate);
    thrown.expect(IOException.class);
    adaptor.init(context);
  }

  @Test
  public void testAdaptorInitUncDenyShareAclAccess() throws Exception {
    root = new DenyShareAclAccessMockFile(ROOT, true);
    delegate = new MockFileDelegate(root);
    adaptor = new FsAdaptor(delegate);
    thrown.expect(IOException.class);
    adaptor.init(context);
  }

  @Test
  public void testAdaptorInitUncDenyDfsShareAclAccess() throws Exception {
    root = new DenyDfsShareAclAccessMockFile(ROOT, true);
    delegate = new MockFileDelegate(root);
    adaptor = new FsAdaptor(delegate);
    adaptor.init(context);
  }

  @Test
  public void testAdaptorInitDfsDenyShareAclAccess() throws Exception {
    root = new DenyShareAclAccessMockFile(ROOT, true);
    root.setDfsActiveStorage(Paths.get("\\\\dfshost\\share"));
    root.setDfsShareAclView(MockFile.FULL_ACCESS_ACLVIEW);
    delegate = new MockFileDelegate(root);
    adaptor = new FsAdaptor(delegate);
    thrown.expect(IOException.class);
    adaptor.init(context);
  }

  @Test
  public void testAdaptorInitDfsDenyDfsShareAclAccess() throws Exception {
    root = new DenyDfsShareAclAccessMockFile(ROOT, true);
    root.setDfsActiveStorage(Paths.get("\\\\dfshost\\share"));
    delegate = new MockFileDelegate(root);
    adaptor = new FsAdaptor(delegate);
    thrown.expect(IOException.class);
    adaptor.init(context);
  }

  @Test
  public void testAdaptorInitLastAccessDays() throws Exception {
    config.overrideKey("filesystemadaptor.lastAccessedDays", "365");
    adaptor.init(context);
  }

  @Test
  public void testAdaptorInitInvalidLastAccessDaysNonNumeric()
      throws Exception {
    config.overrideKey("filesystemadaptor.lastAccessedDays", "ten");
    thrown.expect(InvalidConfigurationException.class);
    adaptor.init(context);
  }

  @Test
  public void testAdaptorInitInvalidLastAccessDaysNegative() throws Exception {
    config.overrideKey("filesystemadaptor.lastAccessedDays", "-365");
    thrown.expect(InvalidConfigurationException.class);
    adaptor.init(context);
  }

  @Test
  public void testAdaptorInitLastAccessDate() throws Exception {
    config.overrideKey("filesystemadaptor.lastAccessedDate", "2000-01-31");
    adaptor.init(context);
  }

  @Test
  public void testAdaptorInitInvalidLastAccessDate() throws Exception {
    config.overrideKey("filesystemadaptor.lastAccessedDate", "01/31/2000");
    thrown.expect(InvalidConfigurationException.class);
    adaptor.init(context);
  }

  @Test
  public void testAdaptorInitFutureLastAccessDate() throws Exception {
    config.overrideKey("filesystemadaptor.lastAccessedDate", "2999-12-31");
    thrown.expect(InvalidConfigurationException.class);
    adaptor.init(context);
  }

  @Test
  public void testAdaptorInitInvalidLastAccessDaysAndDate() throws Exception {
    config.overrideKey("filesystemadaptor.lastAccessedDays", "365");
    config.overrideKey("filesystemadaptor.lastAccessedDate", "2000-01-31");
    thrown.expect(InvalidConfigurationException.class);
    adaptor.init(context);
  }

  @Test
  public void testAdaptorInitLastModifiedDays() throws Exception {
    config.overrideKey("filesystemadaptor.lastModifiedDays", "365");
    adaptor.init(context);
  }

  @Test
  public void testAdaptorInitInvalidLastModifiedDaysNonNumeric()
      throws Exception {
    config.overrideKey("filesystemadaptor.lastModifiedDays", "ten");
    thrown.expect(InvalidConfigurationException.class);
    adaptor.init(context);
  }

  @Test
  public void testAdaptorInitInvalidLastModifiedDaysNegative()
      throws Exception {
    config.overrideKey("filesystemadaptor.lastModifiedDays", "-365");
    thrown.expect(InvalidConfigurationException.class);
    adaptor.init(context);
  }

  @Test
  public void testAdaptorInitLastModifiedDate() throws Exception {
    config.overrideKey("filesystemadaptor.lastModifiedDate", "2000-01-31");
    adaptor.init(context);
  }

  @Test
  public void testAdaptorInitInvalidLastModifiedDate() throws Exception {
    config.overrideKey("filesystemadaptor.lastModifiedDate", "01/31/2000");
    thrown.expect(InvalidConfigurationException.class);
    adaptor.init(context);
  }

  @Test
  public void testAdaptorInitFutureLastModifiedDate() throws Exception {
    config.overrideKey("filesystemadaptor.lastAccessedDate", "2999-12-31");
    thrown.expect(InvalidConfigurationException.class);
    adaptor.init(context);
  }

  @Test
  public void testAdaptorInitInvalidLastModifiedDaysAndDate() throws Exception {
    config.overrideKey("filesystemadaptor.lastModifiedDays", "365");
    config.overrideKey("filesystemadaptor.lastModifiedDate", "2000-01-31");
    thrown.expect(InvalidConfigurationException.class);
    adaptor.init(context);
  }

  @Test
  public void testAbsoluteLastAccessTimeFilterTooEarly() throws Exception {
    config.overrideKey("filesystemadaptor.lastAccessedDate", "2000-01-31");
    testLastAccessTimeFilter("2000-01-30", true);
  }

  @Test
  public void testAbsoluteLastAccessTimeFilterStartDate() throws Exception {
    config.overrideKey("filesystemadaptor.lastAccessedDate", "2000-01-31");
    testLastAccessTimeFilter("2000-01-31", false);
  }

  @Test
  public void testAbsoluteLastAccessTimeFilterMuchLater() throws Exception {
    config.overrideKey("filesystemadaptor.lastAccessedDate", "2000-01-31");
    testLastAccessTimeFilter("2014-01-31", false);
  }

  @Test
  public void testRelativeLastAccessTimeFilterTooEarly() throws Exception {
    config.overrideKey("filesystemadaptor.lastAccessedDays", "1");
    long yesterday = System.currentTimeMillis() - (25 * 60 * 60 * 1000L);
    testLastAccessTimeFilter(yesterday, true);
  }

  @Test
  public void testRelativeLastAccessTimeFilterStartTime() throws Exception {
    config.overrideKey("filesystemadaptor.lastAccessedDays", "1");
    long squeekedBy = System.currentTimeMillis() - (24 * 59 * 60 * 1000L);
    testLastAccessTimeFilter(squeekedBy, false);
  }

  @Test
  public void testRelativeLastAccessTimeFilterMuchLater() throws Exception {
    config.overrideKey("filesystemadaptor.lastAccessedDays", "1");
    long now = System.currentTimeMillis();
    testLastAccessTimeFilter(now, false);
  }

  private void testLastAccessTimeFilter(String date, boolean excluded)
      throws Exception {
    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
    dateFormat.setCalendar(Calendar.getInstance());
    dateFormat.setLenient(true);
    testLastAccessTimeFilter(dateFormat.parse(date).getTime(), excluded);
  }

  private void testLastAccessTimeFilter(long fileTime, boolean excluded)
      throws Exception {
    MockFile file = new MockFile("test.html");
    file.setLastAccessTime(FileTime.fromMillis(fileTime));
    testFileTimeFilter(file, excluded);
  }

  private void testFileTimeFilter(MockFile file, boolean excluded)
      throws Exception {
    file.setFileContents("<html><title>Hello World</title></html>");
    file.setContentType("text/html");
    root.addChildren(file);
    adaptor.init(context);
    MockRequest request = new MockRequest(getDocId(file.getPath()));
    MockResponse response = new MockResponse();
    adaptor.getDocContent(request, response);
    assertEquals(excluded, response.notFound);
  }

  @Test
  public void testAbsoluteLastModifiedTimeFilterTooEarly() throws Exception {
    config.overrideKey("filesystemadaptor.lastModifiedDate", "2000-01-31");
    testLastModifiedTimeFilter("2000-01-30", true);
  }

  @Test
  public void testAbsoluteLastModifiedTimeFilterStartDate() throws Exception {
    config.overrideKey("filesystemadaptor.lastModifiedDate", "2000-01-31");
    testLastModifiedTimeFilter("2000-01-31", false);
  }

  @Test
  public void testAbsoluteLastModifiedTimeFilterMuchLater() throws Exception {
    config.overrideKey("filesystemadaptor.lastModifiedDate", "2000-01-31");
    testLastModifiedTimeFilter("2014-01-31", false);
  }

  @Test
  public void testRelativeLastModifiedTimeFilterTooEarly() throws Exception {
    config.overrideKey("filesystemadaptor.lastModifiedDays", "1");
    long yesterday = System.currentTimeMillis() - (25 * 60 * 60 * 1000L);
    testLastModifiedTimeFilter(yesterday, true);
  }

  @Test
  public void testRelativeLastModifiedTimeFilterStartTime() throws Exception {
    config.overrideKey("filesystemadaptor.lastModifiedDays", "1");
    long squeekedBy = System.currentTimeMillis() - (24 * 59 * 60 * 1000L);
    testLastModifiedTimeFilter(squeekedBy, false);
  }

  @Test
  public void testRelativeLastModifiedTimeFilterMuchLater() throws Exception {
    config.overrideKey("filesystemadaptor.lastModifiedDays", "1");
    long now = System.currentTimeMillis();
    testLastModifiedTimeFilter(now, false);
  }

  private void testLastModifiedTimeFilter(String date, boolean excluded)
      throws Exception {
    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
    dateFormat.setCalendar(Calendar.getInstance());
    dateFormat.setLenient(true);
    testLastModifiedTimeFilter(dateFormat.parse(date).getTime(), excluded);
  }

  private void testLastModifiedTimeFilter(long fileTime, boolean excluded)
      throws Exception {
    MockFile file = new MockFile("test.html");
    file.setLastModifiedTime(FileTime.fromMillis(fileTime));
    testFileTimeFilter(file, excluded);
  }

  private static class DenyShareAclAccessMockFile extends MockFile {
    DenyShareAclAccessMockFile(String name, boolean isDirectory) {
      super(name, isDirectory);
    }
    @Override
    AclFileAttributeView getShareAclView() throws IOException {
      throw new IOException("Access is denied.");
    }
  }

  private static class DenyDfsShareAclAccessMockFile extends MockFile {
    DenyDfsShareAclAccessMockFile(String name, boolean isDirectory) {
      super(name, isDirectory);
    }
    @Override
    AclFileAttributeView getDfsShareAclView() throws IOException {
      throw new IOException("Access is denied.");
    }
  }

  /** Returns an AclBuilder for the AclFileAttributeView. */
  private AclBuilder newBuilder(AclFileAttributeView aclView) {
    return new AclBuilder(Paths.get("foo", "bar"),
        aclView, windowsAccounts, builtinPrefix, namespace);
  }
}
