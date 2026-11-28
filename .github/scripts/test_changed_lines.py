import unittest

import changed_lines

DIFF = """diff --git a/src/A.java b/src/A.java
--- a/src/A.java
+++ b/src/A.java
@@ -3,0 +4,2 @@ class A {
+  int x;
+  int y;
@@ -10 +12 @@ class A {
-  old();
+  new();
@@ -20,3 +22,0 @@ class A {
-  gone();
diff --git a/src/B.java b/src/B.java
deleted file mode 100644
--- a/src/B.java
+++ /dev/null
@@ -1,2 +0,0 @@
-class B {
-}
"""


class ChangedLinesTest(unittest.TestCase):

    def test_the_new_side_of_each_hunk_and_nothing_deleted(self):
        found = changed_lines.changed(DIFF)
        self.assertEqual({"src/A.java": {4, 5, 12}}, found)


if __name__ == "__main__":
    unittest.main()
