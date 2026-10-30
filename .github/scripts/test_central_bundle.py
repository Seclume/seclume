import os
import tempfile
import textwrap
import unittest

import central_bundle

POM = textwrap.dedent('''\
    <project xmlns="http://maven.apache.org/POM/4.0.0">
      <artifactId>{artifact}</artifactId>
      {packaging}
      {properties}
      <modules>{modules}</modules>
      {profiles}
    </project>''')

PROFILES = textwrap.dedent('''\
    <profiles>
      <profile><id>release</id><build><plugins>
        {sbom}
      </plugins></build></profile>
      <profile><id>central</id><build><plugins>
        <plugin><artifactId>central-publishing-maven-plugin</artifactId>
          <configuration>{checksums}
            <excludeArtifacts><artifact>excluded</artifact></excludeArtifacts>
          </configuration></plugin>
      </plugins></build></profile>
    </profiles>''')


def project(root, checksums, sbom=True):
    def pom(directory, artifact, packaging='', modules=(), properties='', profiles=''):
        os.makedirs(directory, exist_ok=True)
        with open(os.path.join(directory, 'pom.xml'), 'w', encoding='utf-8') as f:
            f.write(POM.format(artifact=artifact, packaging=packaging, properties=properties,
                               modules=''.join(f'<module>{m}</module>' for m in modules),
                               profiles=profiles))
    pom(root, 'parent', '<packaging>pom</packaging>', ['core', 'bench', 'excluded', 'group'],
        profiles=PROFILES.format(
            sbom='<plugin><artifactId>cyclonedx-maven-plugin</artifactId></plugin>' if sbom else '',
            checksums=f'<checksums>{checksums}</checksums>' if checksums else ''))
    pom(os.path.join(root, 'core'), 'core')
    pom(os.path.join(root, 'bench'), 'bench',
        properties='<properties><maven.deploy.skip>true</maven.deploy.skip></properties>')
    pom(os.path.join(root, 'excluded'), 'excluded')
    pom(os.path.join(root, 'group'), 'group', '<packaging>pom</packaging>', ['inner'])
    pom(os.path.join(root, 'group', 'inner'), 'inner')


class CentralBundleTest(unittest.TestCase):

    def counted(self, checksums, sbom=True):
        with tempfile.TemporaryDirectory() as root:
            project(root, checksums, sbom)
            return {artifact: n for artifact, _, n in central_bundle.count(root)}

    def test_all_checksums_are_four_per_artifact_and_none_for_signatures(self):
        # A jar module: pom, jar, sources, javadoc, SBOM - each with .asc and 4 checksums.
        counted = self.counted(None)
        self.assertEqual(30, counted['core'])
        self.assertEqual(30, counted['inner'])
        self.assertEqual(12, counted['parent'])   # pom and SBOM
        self.assertEqual(12, counted['group'])

    def test_required_checksums_are_md5_and_sha1(self):
        counted = self.counted('required')
        self.assertEqual(20, counted['core'])
        self.assertEqual(8, counted['parent'])
        self.assertEqual(10, self.counted('none')['core'])   # 5 artifacts, 5 signatures

    def test_skipped_and_excluded_modules_add_nothing(self):
        counted = self.counted('required')
        self.assertEqual(0, counted['bench'])
        self.assertEqual(0, counted['excluded'])

    def test_without_an_sbom_a_module_has_one_artifact_less(self):
        self.assertEqual(16, self.counted('required', sbom=False)['core'])

    def test_the_check_fails_at_the_limit(self):
        with tempfile.TemporaryDirectory() as root:
            project(root, 'all')
            total = sum(n for _, _, n in central_bundle.count(root))
            self.assertEqual(1, central_bundle.main([root, '--limit', str(total)]))
            self.assertEqual(0, central_bundle.main([root, '--limit', str(total + 1)]))

    def test_this_repository_fits(self):
        root = os.path.join(os.path.dirname(__file__), '..', '..')
        self.assertEqual(0, central_bundle.main([root]))


if __name__ == '__main__':
    unittest.main()
