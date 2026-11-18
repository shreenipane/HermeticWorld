# Maven Ecosystem Cutoff & Sealing: Research Note

- **Status:** Phase 4 Research Note
- **Date:** 2026-11-18
- **Context:** Extension of Hermetic World (§6.4 of [HERMETIC_WORLD_ARCHITECTURE.md](../HERMETIC_WORLD_ARCHITECTURE.md)) to Java/JVM ecosystems.

---

## 1. Executive Summary

Supporting Apache Maven and Java/JVM build tools (Gradle, sbt) in Hermetic World requires sealing the dependency resolution graph as of an exact cutoff timestamp $T_{\text{world}}$.

Unlike PyPI (PEP 700 `upload-time`), crates.io (`pubtime`), or npm (`time` map), standard Maven repositories do not record per-version publication timestamps in their repository metadata files. A repository `maven-metadata.xml` records only a single `<lastUpdated>` timestamp for the coordinate as a whole. Consequently, an upstream `maven-metadata.xml` cannot be filtered in place to discover which releases existed prior to the cutoff date.

To seal Maven environments without temporal leakage or reliance on unauthenticated host timestamps, Hermetic World must employ **dated repository index provenance** (such as Sonatype Central Lucene index archives) or **dated immutable-manifest provenance**, alongside recording proxies that capture the full hierarchy of parent POMs, BOM imports, and build plugin dependencies.

---

## 2. Maven Repository Structure & Protocol

Maven uses a deterministic, directory-based HTTP repository layout:

```text
https://repo.maven.apache.org/maven2/{group_path}/{artifact}/{version}/{artifact}-{version}[-{classifier}].{extension}
```

For example:
- POM: `org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.pom`
- JAR: `org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar`
- Metadata: `org/apache/commons/commons-lang3/maven-metadata.xml`

### 2.1 Release Metadata Schema

A standard release `maven-metadata.xml` has the following schema:

```xml
<metadata>
  <groupId>org.apache.commons</groupId>
  <artifactId>commons-lang3</artifactId>
  <versioning>
    <latest>3.14.0</latest>
    <release>3.14.0</release>
    <versions>
      <version>3.10</version>
      <version>3.11</version>
      <version>3.12.0</version>
      <version>3.13.0</version>
      <version>3.14.0</version>
    </versions>
    <lastUpdated>20231215180000</lastUpdated>
  </versioning>
</metadata>
```

**Key Observation:** `<lastUpdated>` is updated whenever *any* new version is deployed. It reflects the date of the newest deployment, not individual versions. Versions 3.10 through 3.13.0 have no timestamps in this file.

### 2.2 Snapshot Repositories and Mutability

Maven snapshots (`-SNAPSHOT`) allow mutable artifacts deployed with incremental build numbers:

```xml
<metadata>
  <groupId>com.example</groupId>
  <artifactId>my-app</artifactId>
  <version>1.0.0-SNAPSHOT</version>
  <versioning>
    <snapshot>
      <timestamp>20230301.120000</timestamp>
      <buildNumber>3</buildNumber>
    </snapshot>
    <lastUpdated>20230301120000</lastUpdated>
    <snapshotVersions>
      <snapshotVersion>
        <extension>jar</extension>
        <value>1.0.0-20230301.120000-3</value>
        <updated>20230301120000</updated>
      </snapshotVersion>
    </snapshotVersions>
  </versioning>
</metadata>
```

Snapshots present severe hermeticity risks:
1. Repositories regularly purge older timestamped snapshots, retaining only the latest.
2. A non-unique snapshot (`1.0.0-SNAPSHOT.jar`) has no cryptographic timestamp binding.
3. In Hermetic World, mutable snapshots must be forbidden unless pinned to an exact immutable timestamped identifier (`1.0.0-YYYYMMDD.HHMMSS-B`) verified at or before $T_{\text{world}}$.

---

## 3. Dependency Graph Complexities in Maven

Resolving a Maven build is substantially more complex than Python or npm because Maven project descriptors (`pom.xml`) participate in multi-tiered inheritance and dynamic execution:

### 3.1 Parent POM Hierarchies
A module POM frequently inherits from a parent POM (`<parent>`), which may inherit from another parent POM:
- Parent POMs specify compiler targets, plugin versions, and default dependencies.
- A missing or unsealed parent POM prevents the project from parsing.
- Each parent POM must be independently checked for cutoff compliance.

### 3.2 BOM (Bill of Materials) Imports
Projects use `<dependencyManagement>` with `<scope>import</scope>` to import versions from remote BOM POMs (e.g., `spring-boot-dependencies`, `jackson-bom`). All imported BOMs must be sealed as of $T_{\text{world}}$.

### 3.3 Maven Plugin and Build-Extension Dependencies
Unlike pip or npm, where build tools are typically installed prior to execution, Maven dynamically downloads **plugins** during the build lifecycle:
- Core plugins (`maven-compiler-plugin`, `maven-surefire-plugin`, `maven-jar-plugin`).
- Plugins declared in POMs have their own transitive dependency trees.
- Plugins can pull build-time dependencies (e.g. annotation processors, checkstyle definitions) dynamically.
- An offline store must contain the complete transitive closure of all plugins invoked by the build phases (`compile`, `test`, `package`).

---

## 4. Proposed Sealing Architecture for Maven

To integrate Maven into the existing Hermetic World offline store and WorldServer (`DirStore`), the following architecture is required:

### 4.1 Provenance Sources
1. **Central Repository Index Dumps:**
   - Central Maven publishes daily indexes (`nexus-maven-repository-index.gz`).
   - Each entry contains coordinate, packaging, sha1, size, and **last-modified timestamp**.
   - These timestamps establish genuine, third-party publication dates for artifacts.
2. **Deterministic Recipe Manifest:**
   - Following `python/hermetic_ecosystem_cut/mirror.py`, a Maven recipe must specify:
     ```json
     {
       "ecosystem": "maven",
       "groupId": "org.apache.commons",
       "artifactId": "commons-lang3",
       "artifacts": {
         "3.12.0.pom": "<sha256>",
         "3.12.0.jar": "<sha256>"
       },
       "publication_times": {
         "3.12.0": "2021-03-05T14:30:00Z"
       }
     }
     ```

### 4.2 Metadata Reconstruction
1. Filter versions where `publication_time <= T_world`.
2. Generate synthetic, deterministic `maven-metadata.xml` containing only admitted versions.
3. Set `<lastUpdated>` to $\min(\text{newest admitted publish time}, T_{\text{world}})$.
4. Set `<release>` and `<latest>` to the highest admitted stable version.

### 4.3 Rootfs and Client Isolation
1. Point Maven to WorldServer authority (`https://repo.maven.apache.org/maven2` or internal mirror) via `/etc/hermetic/settings.xml`:
   ```xml
   <settings>
     <mirrors>
       <mirror>
         <id>hermetic-world</id>
         <url>https://repo.maven.apache.org/maven2</url>
         <mirrorOf>*</mirrorOf>
       </mirror>
     </mirrors>
     <offline>false</offline>
   </settings>
   ```
2. Disable external repository discovery in POMs (`--no-transfer-progress`, strict settings).
3. Populate local repository cache (`~/.m2/repository`) with pre-warmed build dependencies if needed for offline execution.

---

## 5. Security & Isolation Invariants

1. **XML Parser Hardening:**
   - Maven POM and metadata parsers must disable external entity resolution (XXE prevention: `disallow-doctype-decl`).
   - Limit XML recursion depth to 24 levels and document size to 16 MiB.
2. **Strict SHA-256 and SHA-1 Validation:**
   - Maven uses SHA-1 and MD5 legacy checksum sidecars (`.sha1`, `.md5`).
   - Hermetic World must verify strong SHA-256 for all stored blobs, and synthesize canonical `.sha1` and `.md5` sidecars inside `world/store` to satisfy Maven client verification.
3. **Fail-Closed on Unverified Dates:**
   - If an artifact's publication timestamp cannot be established from verified index dumps or recipe manifests, it must be excluded. Local filesystem mtimes or POM creation dates must never be used.
