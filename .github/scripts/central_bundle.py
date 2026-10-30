#!/usr/bin/env python3
"""How many files a release puts into the Maven Central bundle - before it is built.

Central refuses a deployment of 1,000 files or more. A release learns that at
upload, after the tag is signed; this check learns it on every pull request,
from the module list and the release configuration in the poms:

* every module that is deployed adds its pom, and its CycloneDX SBOM when the
  release profile makes one; a jar module its jar, sources and javadoc jars too;
* every one of those artifacts gets a .asc signature;
* every artifact - not the signatures - gets one checksum per algorithm of the
  central plugin's <checksums>: all = MD5, SHA-1, SHA-256, SHA-512; required =
  MD5, SHA-1; none = none.

A module is not deployed when it sets maven.deploy.skip or skipPublishing, or
when the central profile names it in excludeArtifacts.

usage: central_bundle.py [root] [--limit N]   exit 1 when the bundle reaches N (1000)
"""
import os
import re
import sys
# The repository's own poms, not input from outside; Python's expat resolves no
# external entities and limits entity expansion.
import xml.etree.ElementTree as ET  # nosemgrep

NS = {'m': 'http://maven.apache.org/POM/4.0.0'}
CHECKSUMS = {'all': 4, 'required': 2, 'none': 0}
LIMIT = 1000


def _text(element, path):
    found = element.find(path, NS)
    return found.text.strip() if found is not None and found.text else None


def _profile(project, profile_id):
    for profile in project.findall('m:profiles/m:profile', NS):
        if _text(profile, 'm:id') == profile_id:
            return profile
    return None


def _plugin(container, artifact_id):
    if container is None:
        return None
    for plugin in container.findall('m:build/m:plugins/m:plugin', NS):
        if _text(plugin, 'm:artifactId') == artifact_id:
            return plugin
    return None


def modules(root):
    """(directory, artifactId, packaging, skipped) for every module, depth first."""
    found = []

    def walk(directory):
        # nosemgrep - the repository's own pom, see the import
        project = ET.parse(os.path.join(directory, 'pom.xml')).getroot()
        artifact = _text(project, 'm:artifactId')
        packaging = _text(project, 'm:packaging') or 'jar'
        raw = open(os.path.join(directory, 'pom.xml'), encoding='utf-8').read()
        skipped = bool(re.search(r'<(maven\.deploy\.skip|skipPublishing)>\s*true\s*<', raw))
        found.append((directory, artifact, packaging, skipped))
        for module in project.findall('m:modules/m:module', NS):
            walk(os.path.join(directory, module.text.strip()))

    walk(root)
    return found


def settings(root):
    """The central plugin's checksum count and exclusions, and whether SBOMs are made."""
    # nosemgrep - the repository's own pom, see the import
    project = ET.parse(os.path.join(root, 'pom.xml')).getroot()
    central = _plugin(_profile(project, 'central'), 'central-publishing-maven-plugin')
    if central is None:
        raise SystemExit('no central-publishing-maven-plugin in the central profile')
    checksums = (_text(central, 'm:configuration/m:checksums') or 'all').lower()
    if checksums not in CHECKSUMS:
        raise SystemExit('unknown <checksums> ' + checksums)
    excluded = {a.text.strip() for a in
                central.findall('m:configuration/m:excludeArtifacts/m:artifact', NS)}
    sbom = _plugin(_profile(project, 'release'), 'cyclonedx-maven-plugin') is not None
    return CHECKSUMS[checksums], excluded, sbom


def files(packaging, checksums, sbom):
    """The files one deployed module puts into the bundle."""
    artifacts = 1 + (1 if sbom else 0) + (3 if packaging != 'pom' else 0)
    return artifacts * (2 + checksums)          # itself, its .asc, its checksums


def count(root):
    checksums, excluded, sbom = settings(root)
    rows = []
    for directory, artifact, packaging, skipped in modules(root):
        deployed = not skipped and artifact not in excluded
        rows.append((artifact, packaging, files(packaging, checksums, sbom) if deployed else 0))
    return rows


def main(argv):
    root, limit = '.', LIMIT
    rest = list(argv)
    while rest:
        argument = rest.pop(0)
        if argument == '--limit':
            limit = int(rest.pop(0))
        else:
            root = argument
    rows = count(root)
    total = sum(n for _, _, n in rows)
    for artifact, packaging, n in rows:
        print(f'{n:5d}  {artifact} ({packaging})' if n else f'    -  {artifact} (not deployed)')
    print(f'{total:5d}  files in the Maven Central bundle, limit {limit}')
    if total >= limit:
        print(f'the bundle has {total} files: Central refuses a deployment of {limit} or more. '
              'Reduce the checksums, or leave internal modules out of the deployment.')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
