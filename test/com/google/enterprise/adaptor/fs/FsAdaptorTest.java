// Copyright 2013 Google Inc. All Rights Reserved.
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

import com.google.enterprise.adaptor.fs.MockDirectoryBuilder.ConfigureFile;

import org.junit.*;
import org.junit.rules.ExpectedException;

import java.nio.file.Paths;

/** Test cases for {@link FsAdaptor}. */
public class FsAdaptorTest {
  private MockDirectoryBuilder builder;
  private MockFileDelegate delegate;
  private FsAdaptor adaptor;
  private Config config;

  @Override
  protected void setUp() {
    builder = new MockDirectoryBuilder();
    delegate = new MockFileDelegate(builder);
    adaptor = new FsAdaptor(delegate);
    config = new Config();
    adaptor.initConfig(config);
  }

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  @Test
  public void testGetPathName() throws Exception {
    assertEquals("share", adaptor.getPathName(Paths.get("\\\\host/share/")));
    assertEquals("folder2", 
        adaptor.getPathName(Paths.get("C:/folder1/folder2/")));
    assertEquals("foo.text", 
        adaptor.getPathName(Paths.get("C:/folder1/foo.txt")));
    assertEquals("bug-test", adaptor.getPathName(Paths.get("\\\\\brwsr-xp.gdc-psl.net/bug-test/")));
  }

  @Test
  public void testIsSupportedPath() throws Exception {
    ConfigureFile configureFile = new ConfigureFile() {
        public boolean configure(MockFile file) {
          if ("link".equals(file.getName())) {
            file.setIsDirectory(false);
            file.setIsRegularFile(false);
            return false;
          }
          return true;
        }
      };
    builder.addDir(configureFile, null, "/root", "foo", "link", "bar");

    assertTrue(adaptor.isSupportedPath(delegate.getPath("/root")));
    assertTrue(adaptor.isSupportedPath(delegate.getPath("/root/foo")));
    assertTrue(adaptor.isSupportedPath(delegate.getPath("/root/bar")));
    assertFalse(adaptor.isSupportedPath(delegate.getPath("/root/link")));
  }
  /*
  @Test
  public void testIsVisibleDescendantOfRoot() throws Exception {
    ConfigureFile configureFile = new ConfigureFile() {
        public boolean configure(MockFile file) {
          if ("hidden".equals(file.getName())) {
            file.setIsHidden(true);
            return false;
          }
          return true;
        }
      };
    MockFile root = builder.addDir(null, "/", "foo");
    builder.addDir(configureFile, root, "dir1", "bar", "hidden");
    MockFile dir2 = builder.addDir(configureFile, root, "dir2", "baz");
    builder.addDir(configureFile, dir2, "hidden", "foobar");

    assertTrue(adaptor.isSupportedPath(delegate.getPath("/root")));
    assertTrue(adaptor.isSupportedPath(delegate.getPath("/root/foo")));
    assertTrue(adaptor.isSupportedPath(delegate.getPath("/root/bar")));
    assertFalse(adaptor.isSupportedPath(delegate.getPath("/root/link")));
  }
  
  */

}
