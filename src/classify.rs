use anyhow::{Context, Result, bail};
use ignore::Match;
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use std::fs;
use std::path::{Component, Path, PathBuf};

const BUILTIN_IGNORES: &[&str] = &[
    "/target/",
    "node_modules/",
    ".venv/",
    "venv/",
    "__pycache__/",
    ".pytest_cache/",
    ".mypy_cache/",
    ".ruff_cache/",
    ".tox/",
    ".gradle/",
    ".next/",
    ".turbo/",
    ".parcel-cache/",
    ".build/",
    "*.pyc",
    "*.pyo",
    "*.tsbuildinfo",
    ".DS_Store",
    "Thumbs.db",
];
pub const CURRENT_CLASSIFICATION_VERSION: u32 = 2;

#[derive(Clone, Debug)]
pub(crate) struct ClassificationPolicy {
    pub version: u32,
    pub patterns: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct Classifier {
    root: PathBuf,
    matcher: Gitignore,
    version: u32,
    patterns: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Classification {
    pub portable: bool,
    pub reason: String,
}

impl Classifier {
    pub fn load(root: &Path) -> Result<Self> {
        Self::load_with_global(root, &global_rules_path()?)
    }

    fn load_with_global(root: &Path, global_path: &Path) -> Result<Self> {
        let repo_path = root.join(".pandoignore");
        let global_patterns = read_patterns(global_path)?;
        let repo_patterns = read_patterns(&repo_path)?;
        Self::from_sources(
            root,
            CURRENT_CLASSIFICATION_VERSION,
            (global_path, &global_patterns),
            (&repo_path, &repo_patterns),
        )
    }

    pub fn from_policy(root: &Path, version: u32, patterns: Vec<String>) -> Result<Self> {
        let source = root.join(".pandoignore");
        Self::from_sources(root, version, (&source, &[]), (&source, &patterns))
    }

    fn from_sources(
        root: &Path,
        version: u32,
        global: (&Path, &[String]),
        repository: (&Path, &[String]),
    ) -> Result<Self> {
        if version > CURRENT_CLASSIFICATION_VERSION {
            bail!(
                "snapshot classification version {version} is newer than supported version {CURRENT_CLASSIFICATION_VERSION}"
            );
        }
        let mut builder = GitignoreBuilder::new(root);
        if version >= 1 {
            for pattern in BUILTIN_IGNORES {
                builder.add_line(None, pattern)?;
            }
        }
        for pattern in global.1 {
            builder.add_line(Some(global.0.to_owned()), pattern)?;
        }
        for pattern in repository.1 {
            builder.add_line(Some(repository.0.to_owned()), pattern)?;
        }
        let patterns = global.1.iter().chain(repository.1).cloned().collect();
        Ok(Self {
            root: root.to_owned(),
            matcher: builder.build()?,
            version,
            patterns,
        })
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn patterns(&self) -> &[String] {
        &self.patterns
    }

    pub fn is_portable(&self, relative: &Path, is_dir: bool) -> bool {
        let first = relative.components().next();
        if first == Some(Component::Normal(".pando".as_ref())) {
            return false;
        }
        if self.version >= 2 && is_local_git_metadata(relative) {
            return false;
        }
        if first == Some(Component::Normal(".git".as_ref()))
            || relative == Path::new(".pandoignore")
        {
            return true;
        }
        !self
            .matcher
            .matched_path_or_any_parents(self.root.join(relative), is_dir)
            .is_ignore()
    }

    pub fn explain(&self, relative: &Path, is_dir: bool) -> Classification {
        let first = relative.components().next();
        if first == Some(Component::Normal(".pando".as_ref())) {
            return Classification {
                portable: false,
                reason: "reserved root .pando/ is always local".into(),
            };
        }
        if self.version >= 2 && is_local_git_metadata(relative) {
            return Classification {
                portable: false,
                reason: "regenerable machine-local Git bookkeeping".into(),
            };
        }
        if first == Some(Component::Normal(".git".as_ref()))
            || relative == Path::new(".pandoignore")
        {
            return Classification {
                portable: true,
                reason: "Pando metadata required for working-tree continuity".into(),
            };
        }
        match self
            .matcher
            .matched_path_or_any_parents(self.root.join(relative), is_dir)
        {
            Match::Ignore(rule) | Match::Whitelist(rule) => {
                let portable = rule.is_whitelist();
                let source = rule
                    .from()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|| "built-in rules".into());
                Classification {
                    portable,
                    reason: format!("rule {:?} from {source}", rule.original()),
                }
            }
            Match::None => Classification {
                portable: true,
                reason: "portable by default".into(),
            },
        }
    }
}

fn is_local_git_metadata(relative: &Path) -> bool {
    let Some(git_relative) = relative.strip_prefix(".git").ok() else {
        return false;
    };
    git_relative == Path::new(".DS_Store")
        || git_relative == Path::new("FETCH_HEAD")
        || git_relative == Path::new("ORIG_HEAD")
        || git_relative == Path::new("COMMIT_EDITMSG")
        || (git_relative.starts_with("logs/")
            && git_relative != Path::new("logs")
            && git_relative != Path::new("logs/refs")
            && git_relative != Path::new("logs/refs/stash"))
        || git_relative == Path::new("worktrees")
        || git_relative.starts_with("worktrees/")
        || git_relative
            .file_name()
            .is_some_and(|name| name.to_string_lossy().ends_with(".lock"))
}

pub fn global_rules_path() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("PANDO_CONFIG_HOME") {
        return Ok(PathBuf::from(path).join("ignore"));
    }
    if let Some(path) = std::env::var_os("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(path).join("pando").join("ignore"));
    }
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home)
        .join(".config")
        .join("pando")
        .join("ignore"))
}

fn read_patterns(path: &Path) -> Result<Vec<String>> {
    match fs::read_to_string(path) {
        Ok(contents) => Ok(contents.lines().map(str::to_owned).collect()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => {
            Err(error).with_context(|| format!("read classification rules {}", path.display()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CURRENT_CLASSIFICATION_VERSION, Classifier};
    use std::fs;
    use std::path::Path;

    #[test]
    fn future_classification_policy_is_refused() {
        let root = tempfile::tempdir().unwrap();
        assert!(
            Classifier::from_policy(root.path(), CURRENT_CLASSIFICATION_VERSION + 1, Vec::new(),)
                .is_err()
        );
    }

    #[test]
    fn repository_rules_override_user_wide_rules_and_explain_the_winner() {
        let root = tempfile::tempdir().unwrap();
        let global = root.path().join("config/ignore");
        fs::create_dir_all(global.parent().unwrap()).unwrap();
        fs::write(&global, "*.log\n").unwrap();
        fs::write(root.path().join(".pandoignore"), "!keep.log\n").unwrap();

        let classifier = Classifier::load_with_global(root.path(), &global).unwrap();
        let excluded = classifier.explain(Path::new("debug.log"), false);
        let included = classifier.explain(Path::new("keep.log"), false);

        assert!(!excluded.portable);
        assert!(excluded.reason.contains("*.log"));
        assert!(excluded.reason.contains(&global.display().to_string()));
        assert!(included.portable);
        assert!(included.reason.contains("!keep.log"));
        assert!(included.reason.contains(".pandoignore"));
        assert_eq!(
            classifier.patterns(),
            &["*.log".to_owned(), "!keep.log".to_owned()]
        );

        let receiver = Classifier::from_policy(
            root.path(),
            classifier.version(),
            classifier.patterns().to_vec(),
        )
        .unwrap();
        assert!(!receiver.is_portable(Path::new("debug.log"), false));
        assert!(receiver.is_portable(Path::new("keep.log"), false));
    }

    #[test]
    fn explanations_cover_builtins_defaults_and_fixed_paths() {
        let root = tempfile::tempdir().unwrap();
        let classifier =
            Classifier::load_with_global(root.path(), &root.path().join("missing")).unwrap();

        let derived = classifier.explain(Path::new("node_modules/pkg/index.js"), false);
        assert!(!derived.portable);
        assert!(derived.reason.contains("node_modules/"));
        assert!(derived.reason.contains("built-in"));
        assert_eq!(
            classifier.explain(Path::new(".env"), false).reason,
            "portable by default"
        );
        assert!(classifier.explain(Path::new(".git/index"), false).portable);
        assert!(
            classifier
                .explain(Path::new(".git/refs/heads/main"), false)
                .portable
        );
        assert!(
            classifier
                .explain(Path::new(".git/refs/stash"), false)
                .portable
        );
        for path in [
            ".git/.DS_Store",
            ".git/FETCH_HEAD",
            ".git/ORIG_HEAD",
            ".git/COMMIT_EDITMSG",
            ".git/logs/HEAD",
            ".git/worktrees/feature/gitdir",
            ".git/index.lock",
        ] {
            let classification = classifier.explain(Path::new(path), false);
            assert!(!classification.portable, "{path}");
            assert!(classification.reason.contains("Git bookkeeping"));
        }
        let legacy = Classifier::from_policy(root.path(), 1, Vec::new()).unwrap();
        assert!(legacy.is_portable(Path::new(".git/FETCH_HEAD"), false));
        assert!(classifier.is_portable(Path::new(".git/logs/refs/stash"), false));
        assert!(classifier.is_portable(Path::new(".git/refs/remotes/origin/main"), false));
        assert!(
            !classifier
                .explain(Path::new("apps/apple/.build/debug/app"), false)
                .portable
        );
        assert!(
            !classifier
                .explain(Path::new("packages/core/tsconfig.tsbuildinfo"), false)
                .portable
        );
        assert!(
            !classifier
                .explain(Path::new(".pando/state"), false)
                .portable
        );
    }
}
