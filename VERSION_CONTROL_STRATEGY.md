# Version Control Strategy for Draw.io Files

## Current State

The system currently tracks versions using an in-memory `AtomicU64` counter that increments on each change. This provides:
- Real-time collaboration with version numbers
- No persistent version history
- No ability to restore previous versions
- No audit trail of who made changes

## Recommended Strategy: Snapshot-Based Version Control

### Overview

Implement a **snapshot-based version control system** that stores complete file versions with metadata. This approach is:
- Simple and reliable
- Works well with XML-based drawio files
- Easy to restore any version
- Provides full audit trail

### Architecture

#### 1. Storage Structure

```
data/
  ├── file.drawio                    # Current version
  └── .versions/                     # Version history (hidden directory)
      └── file.drawio/
          ├── v1_2024-01-15T10-30-45Z_user1.json
          ├── v2_2024-01-15T10-35-12Z_user2.json
          └── metadata.json          # Version index
```

Each version file contains:
- Full file content
- Version number
- Timestamp (ISO 8601)
- Username who made the change
- Optional: change description/commit message

#### 2. Version Metadata Format

```json
{
  "version": 1,
  "timestamp": "2024-01-15T10:30:45Z",
  "username": "user1",
  "message": "Initial version",
  "file_size": 12345,
  "content_hash": "sha256:abc123..."
}
```

#### 3. Implementation Approach

**Option A: Automatic Versioning (Recommended)**
- Create a version snapshot on every save
- Pros: Never lose history, simple UX
- Cons: Can accumulate many versions quickly

**Option B: Configurable Versioning**
- Create snapshots based on:
  - Time intervals (e.g., every 5 minutes)
  - Significant changes (content hash differs significantly)
  - Manual "checkpoint" requests
- Pros: More storage efficient
- Cons: More complex, might miss some changes

**Option C: Hybrid Approach (Best Balance)**
- Automatic snapshots with:
  - Time-based throttling (max 1 per minute per file)
  - Content-based deduplication (skip if identical to last version)
  - Manual checkpoint API endpoint
- Pros: Good balance of history and storage
- Cons: Moderate complexity

### API Design

#### New Endpoints

```
GET  /api/versions?path=file.drawio
     → List all versions for a file

GET  /api/versions?path=file.drawio&version=5
     → Get specific version content

POST /api/versions/restore?path=file.drawio&version=5
     → Restore a specific version (creates new version)

POST /api/versions/checkpoint?path=file.drawio
     Body: { "message": "Checkpoint description" }
     → Create manual checkpoint

DELETE /api/versions?path=file.drawio&version=5
     → Delete specific version (admin only)

GET  /api/versions/diff?path=file.drawio&from=3&to=5
     → Get diff between versions (optional, for future)
```

#### Response Formats

```json
// GET /api/versions?path=file.drawio
{
  "file": "file.drawio",
  "current_version": 10,
  "versions": [
    {
      "version": 10,
      "timestamp": "2024-01-15T10:45:00Z",
      "username": "user1",
      "message": "Updated diagram",
      "file_size": 12345
    },
    {
      "version": 9,
      "timestamp": "2024-01-15T10:30:00Z",
      "username": "user2",
      "message": "Added new shapes",
      "file_size": 11234
    }
  ]
}
```

### Implementation Details

#### 1. Version Storage Module

Create a new module `src/versioning.rs`:

```rust
pub struct VersionManager {
    data_dir: PathBuf,
    versions_dir: PathBuf,
}

impl VersionManager {
    pub async fn create_version(
        &self,
        file_key: &str,
        content: &str,
        username: &str,
        message: Option<&str>,
    ) -> Result<VersionInfo>;
    
    pub async fn list_versions(&self, file_key: &str) -> Result<Vec<VersionInfo>>;
    
    pub async fn get_version(&self, file_key: &str, version: u64) -> Result<String>;
    
    pub async fn restore_version(
        &self,
        file_key: &str,
        version: u64,
        username: &str,
    ) -> Result<VersionInfo>;
    
    pub async fn delete_version(&self, file_key: &str, version: u64) -> Result<()>;
}
```

#### 2. Integration Points

**In `put_file` and `api_put_file`:**
- After successful write, call `version_manager.create_version()`
- Use current room version number

**In WebSocket handler:**
- After persisting file, create version snapshot
- Throttle: only create version if last version was > 1 minute ago OR content hash changed

**In `api_ai_modify`:**
- Always create version snapshot (AI modifications are significant)

#### 3. Storage Optimization

**Cleanup Strategy:**
- Keep last N versions (e.g., 50) per file
- Keep versions older than X days (e.g., 90 days)
- Optional: Compress old versions (gzip)
- Background task to clean up old versions

**Deduplication:**
- Calculate content hash (SHA-256) before creating version
- Skip if hash matches last version
- Store hash in metadata for quick comparison

## Git-Based Version Control Strategy

### Overview

Use **Git** as the underlying version control system. This leverages a battle-tested, industry-standard tool with excellent storage efficiency and powerful features.

### Architecture

#### 1. Storage Structure

**Option A: Single Repository (Recommended for simplicity)**
```
data/
  ├── .git/                          # Single Git repository
  ├── file1.drawio
  ├── file2.drawio
  └── folder/
      └── file3.drawio
```

**Option B: Per-File Repositories (Better isolation)**
```
data/
  ├── file1.drawio
  ├── .git_file1/                    # Git repo for file1
  ├── file2.drawio
  ├── .git_file2/                    # Git repo for file2
  └── folder/
      ├── file3.drawio
      └── .git_file3/                # Git repo for file3
```

**Option C: Hybrid - Repositories by Directory**
```
data/
  ├── .git/                          # Root repo
  ├── project1/
  │   ├── .git/                      # Project-specific repo
  │   └── files.drawio
  └── project2/
      ├── .git/
      └── files.drawio
```

**Recommendation: Option A (Single Repository)**
- Simplest to manage
- Git handles thousands of files efficiently
- Single `.git` directory
- Easy to backup entire history
- Can use Git's native features (branches, tags, etc.)

#### 2. Git Configuration

```bash
# Initialize repository
git init data/
git config user.name "Draw.io Server"
git config user.email "server@drawio.local"

# Configure for XML files
git config core.autocrlf false
git config core.attributesfile .gitattributes

# Optional: Set up .gitattributes
echo "*.drawio -diff -merge" > data/.gitattributes
# This tells Git to treat .drawio files as binary (no text diffing)
```

#### 3. Commit Strategy

**Commit Message Format:**
```
Version {version_number} by {username}

{optional_message}

Metadata:
- File: {file_path}
- Version: {version_number}
- User: {username}
- Timestamp: {iso_timestamp}
```

**Example:**
```
Version 42 by alice

Updated network diagram with new server

Metadata:
- File: network.drawio
- Version: 42
- User: alice
- Timestamp: 2024-01-15T10:30:45Z
```

### Implementation Approaches

#### Approach 1: Using `git2` Rust Crate (Recommended)

**Dependencies:**
```toml
[dependencies]
git2 = "0.18"
```

**Pros:**
- Pure Rust, no external binary dependency
- Type-safe API
- Good error handling
- Cross-platform

**Cons:**
- Larger binary size
- Requires libgit2 system library or vendored build

**Implementation Structure:**

```rust
// src/git_versioning.rs
use git2::{Repository, Signature, Commit, Oid};
use std::path::PathBuf;

pub struct GitVersionManager {
    repo: Repository,
    data_dir: PathBuf,
}

impl GitVersionManager {
    pub fn new(data_dir: PathBuf) -> Result<Self> {
        let repo_path = &data_dir;
        
        // Initialize or open repository
        let repo = if repo_path.join(".git").exists() {
            Repository::open(repo_path)?
        } else {
            Repository::init(repo_path)?
        };
        
        // Configure repository
        let mut config = repo.config()?;
        config.set_str("user.name", "Draw.io Server")?;
        config.set_str("user.email", "server@drawio.local")?;
        
        Ok(Self { repo, data_dir })
    }
    
    pub async fn create_version(
        &self,
        file_path: &str,
        content: &str,
        username: &str,
        version: u64,
        message: Option<&str>,
    ) -> Result<CommitInfo> {
        // Stage the file
        let mut index = self.repo.index()?;
        let file_path_buf = self.data_dir.join(file_path);
        
        // Write content to file (if not already written)
        // Then add to index
        index.add_path(Path::new(file_path))?;
        index.write()?;
        
        // Create commit
        let tree_id = index.write_tree()?;
        let tree = self.repo.find_tree(tree_id)?;
        
        let signature = Signature::now(
            username,
            &format!("{}@drawio.local", username),
        )?;
        
        let commit_message = format!(
            "Version {} by {}\n\n{}\n\nMetadata:\n- File: {}\n- Version: {}\n- User: {}\n- Timestamp: {}",
            version,
            username,
            message.unwrap_or(""),
            file_path,
            version,
            username,
            chrono::Utc::now().to_rfc3339()
        );
        
        let commit_oid = self.repo.commit(
            Some("HEAD"),
            &signature,
            &signature,
            &commit_message,
            &tree,
            &[], // No parent commits for first commit
        )?;
        
        // Create lightweight tag for version number
        let tag_name = format!("{}/v{}", file_path.replace('/', "_"), version);
        self.repo.tag_lightweight(
            &tag_name,
            &self.repo.find_commit(commit_oid)?,
            false, // Don't force
        )?;
        
        Ok(CommitInfo {
            commit_oid: commit_oid.to_string(),
            version,
            timestamp: chrono::Utc::now(),
            username: username.to_string(),
        })
    }
    
    pub async fn list_versions(
        &self,
        file_path: &str,
    ) -> Result<Vec<VersionInfo>> {
        let mut revwalk = self.repo.revwalk()?;
        revwalk.push_head()?;
        revwalk.set_sorting(git2::Sort::TIME)?;
        
        let mut versions = Vec::new();
        for oid in revwalk {
            let oid = oid?;
            let commit = self.repo.find_commit(oid)?;
            
            // Check if this commit modified our file
            if self.commit_touches_file(&commit, file_path)? {
                let version_info = self.parse_commit_metadata(&commit, file_path)?;
                versions.push(version_info);
            }
        }
        
        Ok(versions)
    }
    
    pub async fn get_version_content(
        &self,
        file_path: &str,
        commit_oid: &str,
    ) -> Result<String> {
        let oid = Oid::from_str(commit_oid)?;
        let commit = self.repo.find_commit(oid)?;
        let tree = commit.tree()?;
        
        let entry = tree.get_path(Path::new(file_path))?;
        let blob = self.repo.find_blob(entry.id())?;
        
        Ok(String::from_utf8_lossy(blob.content()).to_string())
    }
    
    pub async fn restore_version(
        &self,
        file_path: &str,
        commit_oid: &str,
        username: &str,
    ) -> Result<CommitInfo> {
        // Get content from old commit
        let content = self.get_version_content(file_path, commit_oid).await?;
        
        // Write to current file
        let file_path_buf = self.data_dir.join(file_path);
        fs::write(&file_path_buf, content).await?;
        
        // Create new commit (this will be handled by create_version)
        // Return the commit info
        Ok(CommitInfo {
            commit_oid: commit_oid.to_string(),
            version: 0, // Will be set by caller
            timestamp: chrono::Utc::now(),
            username: username.to_string(),
        })
    }
    
    fn commit_touches_file(&self, commit: &Commit, file_path: &str) -> Result<bool> {
        // Compare tree with parent to see if file changed
        if commit.parent_count() == 0 {
            // First commit - check if file exists
            let tree = commit.tree()?;
            return Ok(tree.get_path(Path::new(file_path)).is_ok());
        }
        
        let parent = commit.parent(0)?;
        let parent_tree = parent.tree()?;
        let tree = commit.tree()?;
        
        let parent_entry = parent_tree.get_path(Path::new(file_path));
        let current_entry = tree.get_path(Path::new(file_path));
        
        match (parent_entry, current_entry) {
            (Ok(pe), Ok(ce)) => Ok(pe.id() != ce.id()),
            (Err(_), Ok(_)) => Ok(true), // File added
            (Ok(_), Err(_)) => Ok(true), // File deleted
            (Err(_), Err(_)) => Ok(false), // File didn't exist in either
        }
    }
    
    fn parse_commit_metadata(
        &self,
        commit: &Commit,
        file_path: &str,
    ) -> Result<VersionInfo> {
        let message = commit.message().unwrap_or("");
        let lines: Vec<&str> = message.lines().collect();
        
        // Parse version from first line: "Version {n} by {user}"
        let version = lines.get(0)
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        
        // Parse username
        let username = lines.get(0)
            .and_then(|l| l.split(" by ").nth(1))
            .unwrap_or("unknown")
            .to_string();
        
        // Get timestamp from commit
        let timestamp = chrono::DateTime::from_timestamp(
            commit.time().seconds(),
            0,
        ).unwrap_or_else(|| chrono::Utc::now());
        
        Ok(VersionInfo {
            commit_oid: commit.id().to_string(),
            version,
            timestamp,
            username,
            message: lines.get(2).unwrap_or(&"").to_string(),
        })
    }
}
```

#### Approach 2: Using Git Binary (Alternative)

**Pros:**
- No Rust dependencies
- Uses system Git (if available)
- Familiar Git commands

**Cons:**
- Requires Git binary to be installed
- Process spawning overhead
- Error handling via stdout/stderr parsing
- Less type-safe

**Implementation:**

```rust
use tokio::process::Command;

pub struct GitVersionManager {
    data_dir: PathBuf,
}

impl GitVersionManager {
    pub async fn create_version(
        &self,
        file_path: &str,
        username: &str,
        version: u64,
        message: Option<&str>,
    ) -> Result<String> {
        // Stage file
        Command::new("git")
            .arg("-C")
            .arg(&self.data_dir)
            .arg("add")
            .arg(file_path)
            .status()
            .await?;
        
        // Commit
        let commit_msg = format!(
            "Version {} by {}\n\n{}\n\nMetadata:\n- File: {}\n- Version: {}\n- User: {}\n- Timestamp: {}",
            version, username, message.unwrap_or(""), file_path, version, username,
            chrono::Utc::now().to_rfc3339()
        );
        
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.data_dir)
            .arg("commit")
            .arg("-m")
            .arg(&commit_msg)
            .arg("--author")
            .arg(&format!("{} <{}@drawio.local>", username, username))
            .output()
            .await?;
        
        if !output.status.success() {
            return Err(anyhow::anyhow!("Git commit failed: {}", 
                String::from_utf8_lossy(&output.stderr)));
        }
        
        // Get commit hash
        let hash_output = Command::new("git")
            .arg("-C")
            .arg(&self.data_dir)
            .arg("rev-parse")
            .arg("HEAD")
            .output()
            .await?;
        
        Ok(String::from_utf8_lossy(&hash_output.stdout).trim().to_string())
    }
    
    pub async fn list_versions(&self, file_path: &str) -> Result<Vec<VersionInfo>> {
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.data_dir)
            .arg("log")
            .arg("--pretty=format:%H|%an|%ai|%s")
            .arg("--")
            .arg(file_path)
            .output()
            .await?;
        
        // Parse output and return versions
        // ... parsing logic ...
    }
}
```

### API Design (Same as Snapshot Approach)

The API endpoints remain the same, but implementation uses Git:

```
GET  /api/versions?path=file.drawio
     → git log --pretty=format:... -- file.drawio

GET  /api/versions?path=file.drawio&version=5
     → git show {commit_hash}:file.drawio

POST /api/versions/restore?path=file.drawio&version=5
     → git show {commit_hash}:file.drawio > file.drawio
     → git commit (creates new version)

POST /api/versions/checkpoint?path=file.drawio
     → git add file.drawio && git commit -m "Checkpoint: {message}"

GET  /api/versions/diff?path=file.drawio&from={hash1}&to={hash2}
     → git diff {hash1} {hash2} -- file.drawio
```

### Git-Specific Features

#### 1. Branching Support (Optional)

Allow users to create branches for experimental changes:

```
POST /api/versions/branch?path=file.drawio
Body: { "branch_name": "experimental", "from_version": 10 }
→ git checkout -b experimental v10
```

#### 2. Tags for Important Versions

```
POST /api/versions/tag?path=file.drawio&version=10
Body: { "tag_name": "release-v1.0" }
→ git tag release-v1.0 {commit_hash}
```

#### 3. Merge Support

If branching is enabled:

```
POST /api/versions/merge?path=file.drawio
Body: { "from_branch": "experimental", "to_branch": "main" }
→ git merge experimental
```

### Storage Optimization

#### 1. Git Garbage Collection

```rust
pub async fn gc(&self) -> Result<()> {
    // Run git gc to optimize repository
    Command::new("git")
        .arg("-C")
        .arg(&self.data_dir)
        .arg("gc")
        .arg("--aggressive")
        .arg("--prune=now")
        .output()
        .await?;
    Ok(())
}
```

#### 2. Shallow Clone Option

For very large histories, consider shallow repositories:
```bash
git clone --depth 100 <repo>  # Only last 100 commits
```

#### 3. Git LFS for Large Files (Optional)

If files become very large:
```bash
git lfs track "*.drawio"
```

### Integration Points

#### 1. On File Save

```rust
async fn api_put_file(...) -> impl IntoResponse {
    // ... existing save logic ...
    
    // After successful save
    if let Err(e) = git_manager.create_version(
        &safe,
        &content,
        &username,
        room.version.load(Ordering::SeqCst),
        None,
    ).await {
        error!("Failed to create Git version: {e}");
        // Don't fail the request, but log the error
    }
    
    StatusCode::NO_CONTENT.into_response()
}
```

#### 2. Throttling Strategy

```rust
// Only commit if:
// 1. Last commit was > 1 minute ago, OR
// 2. Content hash changed significantly, OR
// 3. Manual checkpoint requested

let should_commit = {
    let last_commit = get_last_commit_time(&file_path).await?;
    let time_since = now - last_commit;
    time_since > Duration::from_secs(60) || content_hash_changed
};

if should_commit {
    git_manager.create_version(...).await?;
}
```

### Pros and Cons

#### Pros:
- ✅ **Battle-tested**: Git handles edge cases, corruption, concurrent access
- ✅ **Storage efficient**: Git's pack files compress history effectively
- ✅ **Rich features**: Branches, tags, merging, diffing built-in
- ✅ **Tool ecosystem**: Can use standard Git tools (gitk, git log, etc.)
- ✅ **Backup friendly**: Clone entire repo for backup
- ✅ **Audit trail**: Full history with author, timestamp, message
- ✅ **Atomic operations**: Commits are atomic (all-or-nothing)

#### Cons:
- ❌ **Complexity**: More complex than simple snapshots
- ❌ **Dependency**: Requires `git2` crate or Git binary
- ❌ **XML diffs**: Draw.io XML doesn't diff meaningfully (but Git handles this)
- ❌ **Learning curve**: Team needs to understand Git concepts
- ❌ **Repository size**: `.git` directory grows over time
- ❌ **Performance**: Git operations can be slower than direct file access

### Performance Considerations

1. **Async Operations**: All Git operations should be async and non-blocking
2. **Caching**: Cache `git log` results for frequently accessed files
3. **Lazy Loading**: Only load commit history when requested
4. **Background GC**: Run `git gc` periodically in background
5. **Index Management**: Keep Git index updated but don't block on it

### Security Considerations

1. **Repository Access**: Ensure `.git` directory is not web-accessible
2. **Commit Signing**: Optionally sign commits for audit trail
3. **Access Control**: Respect same auth rules as file access
4. **History Protection**: Prevent force-push or history rewriting
5. **Sanitization**: Sanitize commit messages and usernames

### Migration Strategy

If migrating from snapshot-based to Git:

1. **Initialize Git repo** in data directory
2. **Import existing versions** as Git commits (if any)
3. **Start using Git** for new versions
4. **Keep old system** running in parallel during transition
5. **Gradually migrate** old snapshots to Git commits

### Recommended Implementation Plan

1. **Phase 1: Basic Git Integration**
   - Add `git2` dependency
   - Implement `GitVersionManager` with basic commit functionality
   - Integrate into `put_file` and WebSocket handler
   - Add `GET /api/versions` endpoint

2. **Phase 2: Version Retrieval**
   - Implement `get_version_content`
   - Add `GET /api/versions?version={hash}` endpoint
   - Add `POST /api/versions/restore` endpoint

3. **Phase 3: Optimization**
   - Add throttling and deduplication
   - Implement caching for version lists
   - Add background `git gc` task
   - Add manual checkpoint endpoint

4. **Phase 4: Advanced Features (Optional)**
   - Branching support
   - Tagging system
   - Diff visualization
   - Merge capabilities
   - Git LFS for large files

### Comparison: Git vs Snapshot Approach

| Feature | Git Approach | Snapshot Approach |
|---------|-------------|-------------------|
| **Storage Efficiency** | ⭐⭐⭐⭐⭐ (Pack files) | ⭐⭐⭐ (Full copies) |
| **Implementation Complexity** | ⭐⭐⭐ (Moderate) | ⭐⭐ (Simple) |
| **Feature Richness** | ⭐⭐⭐⭐⭐ (Branches, tags, etc.) | ⭐⭐ (Basic) |
| **Performance** | ⭐⭐⭐ (Good) | ⭐⭐⭐⭐ (Excellent) |
| **Dependencies** | ⭐⭐ (git2 or Git binary) | ⭐⭐⭐⭐⭐ (None) |
| **Tool Ecosystem** | ⭐⭐⭐⭐⭐ (Git tools) | ⭐⭐ (Custom only) |
| **Learning Curve** | ⭐⭐⭐ (Git knowledge) | ⭐⭐⭐⭐⭐ (Simple) |

### Conclusion

**Git-based version control is recommended if:**
- You want industry-standard, battle-tested solution
- Storage efficiency is important
- You want advanced features (branches, tags, merging)
- Team is comfortable with Git concepts
- You want to leverage existing Git tooling

**Use snapshot approach if:**
- You want maximum simplicity
- Minimal dependencies are important
- Performance is critical
- You don't need advanced Git features
- Team prefers simpler mental model

### Recommended Implementation Plan

1. **Phase 1: Basic Snapshot System**
   - Implement `VersionManager` module
   - Add version creation on file saves
   - Add `GET /api/versions` endpoint
   - Store versions in `.versions/` directory

2. **Phase 2: Restore Functionality**
   - Add `GET /api/versions?version=N` endpoint
   - Add `POST /api/versions/restore` endpoint
   - Update UI to show version history

3. **Phase 3: Optimization**
   - Add content-based deduplication
   - Add time-based throttling
   - Add cleanup task for old versions
   - Add manual checkpoint endpoint

4. **Phase 4: Advanced Features (Optional)**
   - Version diff visualization
   - Branching/merging (if needed)
   - Export version history
   - Version comparison UI

### Storage Considerations

**Example Storage Usage:**
- Average drawio file: ~50KB
- 100 versions per file: ~5MB
- 1000 files with 100 versions each: ~5GB

**Mitigation:**
- Deduplication reduces storage significantly
- Time-based throttling limits versions
- Cleanup policies remove old versions
- Compression for versions older than 30 days

### Security Considerations

- Version history should respect same auth as file access
- Consider audit logging for version deletions
- Rate limit version creation to prevent abuse
- Sanitize version metadata (usernames, messages)

### Performance Considerations

- Version creation should be async and non-blocking
- Use background task for cleanup operations
- Cache version metadata in memory for frequently accessed files
- Lazy-load version content (only when requested)

## Conclusion

The **Hybrid Snapshot Approach (Option C)** provides the best balance:
- Automatic versioning with smart throttling
- Content-based deduplication
- Manual checkpoint capability
- Simple to implement and maintain
- Good storage efficiency
- Full audit trail

This approach gives users confidence that their work is preserved while keeping storage usage reasonable.

