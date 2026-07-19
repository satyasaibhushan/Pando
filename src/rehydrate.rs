use crate::classify::Classifier;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use walkdir::{DirEntry, WalkDir};

const STATE_VERSION: u32 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Recipe {
    id: String,
    program: &'static str,
    args: &'static [&'static str],
    working_dir: PathBuf,
    inputs: Vec<PathBuf>,
    outputs: &'static [&'static str],
}

impl Recipe {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn program(&self) -> &str {
        self.program
    }

    pub fn args(&self) -> &[&str] {
        self.args
    }

    pub fn working_dir(&self) -> &Path {
        &self.working_dir
    }

    fn fingerprint(&self) -> Result<String> {
        let mut hasher = blake3::Hasher::new();
        hash_field(&mut hasher, self.id.as_bytes());
        hash_field(&mut hasher, self.program.as_bytes());
        hash_field(&mut hasher, self.working_dir.as_os_str().as_encoded_bytes());
        for argument in self.args {
            hash_field(&mut hasher, argument.as_bytes());
        }
        for input in &self.inputs {
            let name = input
                .file_name()
                .context("rehydration input has no file name")?;
            hash_field(&mut hasher, name.as_encoded_bytes());
            let contents = fs::read(input)
                .with_context(|| format!("read rehydration input {}", input.display()))?;
            hash_field(&mut hasher, &contents);
        }
        Ok(hasher.finalize().to_hex().to_string())
    }

    fn execute(&self) -> Result<()> {
        let status = Command::new(self.program)
            .args(self.args)
            .current_dir(&self.working_dir)
            .status()
            .with_context(|| {
                format!(
                    "start rehydration recipe {} in {}",
                    self.id,
                    self.working_dir.display()
                )
            })?;
        if !status.success() {
            bail!("rehydration recipe {} exited with {status}", self.id);
        }
        Ok(())
    }

    fn outputs_ready(&self) -> bool {
        !self.outputs.is_empty()
            && self
                .outputs
                .iter()
                .all(|output| fs::symlink_metadata(self.working_dir.join(output)).is_ok())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HydrationSummary {
    pub ran: Vec<String>,
    pub restored: Vec<String>,
    pub skipped: Vec<String>,
}

impl fmt::Display for HydrationSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "rehydration: ran {}, restored {}, skipped {} unchanged",
            self.ran.len(),
            self.restored.len(),
            self.skipped.len()
        )?;
        if !self.ran.is_empty() {
            write!(formatter, " ({})", self.ran.join(", "))?;
        }
        if !self.restored.is_empty() {
            write!(formatter, " (cache: {})", self.restored.join(", "))?;
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct HydrationState {
    version: u32,
    repo: PathBuf,
    successful: BTreeMap<String, String>,
}

pub struct Hydrator {
    repo: PathBuf,
    state_path: PathBuf,
    artifact_root: PathBuf,
    state: HydrationState,
}

impl Hydrator {
    pub fn open(repo: &Path) -> Result<Self> {
        let canonical = repo
            .canonicalize()
            .with_context(|| format!("resolve repository {}", repo.display()))?;
        let key = blake3::hash(canonical.as_os_str().as_encoded_bytes())
            .to_hex()
            .to_string();
        let state_path = crate::sync::default_data_root()?
            .join("rehydration")
            .join(format!("{key}.json"));
        Self::open_with_state(&canonical, state_path)
    }

    fn open_with_state(repo: &Path, state_path: PathBuf) -> Result<Self> {
        let canonical = repo
            .canonicalize()
            .with_context(|| format!("resolve repository {}", repo.display()))?;
        let state = match fs::read(&state_path) {
            Ok(contents) => {
                let state: HydrationState = serde_json::from_slice(&contents)
                    .with_context(|| format!("parse hydration state {}", state_path.display()))?;
                if state.version != STATE_VERSION {
                    bail!(
                        "unsupported hydration state version {} in {}",
                        state.version,
                        state_path.display()
                    );
                }
                if state.repo != canonical {
                    bail!(
                        "hydration state {} belongs to {} instead of {}",
                        state_path.display(),
                        state.repo.display(),
                        canonical.display()
                    );
                }
                state
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => HydrationState {
                version: STATE_VERSION,
                repo: canonical.clone(),
                successful: BTreeMap::new(),
            },
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("read hydration state {}", state_path.display()));
            }
        };
        Ok(Self {
            repo: canonical,
            state_path,
            artifact_root: crate::sync::default_data_root()?
                .join("artifacts")
                .join(format!(
                    "{}-{}",
                    std::env::consts::OS,
                    std::env::consts::ARCH
                )),
            state,
        })
    }

    pub fn recipes(&self) -> Result<Vec<Recipe>> {
        detect_recipes(&self.repo)
    }

    pub fn run_changed(&mut self, force: bool) -> Result<HydrationSummary> {
        self.run_changed_with_cache(force, true, Recipe::execute)
    }

    #[cfg(test)]
    fn run_changed_with<F>(&mut self, force: bool, run: F) -> Result<HydrationSummary>
    where
        F: FnMut(&Recipe) -> Result<()>,
    {
        self.run_changed_with_cache(force, false, run)
    }

    fn run_changed_with_cache<F>(
        &mut self,
        force: bool,
        use_cache: bool,
        mut run: F,
    ) -> Result<HydrationSummary>
    where
        F: FnMut(&Recipe) -> Result<()>,
    {
        let mut summary = HydrationSummary::default();
        for recipe in self.recipes()? {
            let fingerprint = recipe.fingerprint()?;
            if !force
                && self
                    .state
                    .successful
                    .get(recipe.id())
                    .is_some_and(|saved| saved == &fingerprint)
                && (!use_cache || recipe.outputs.is_empty() || recipe.outputs_ready())
            {
                summary.skipped.push(recipe.id.clone());
                continue;
            }
            if !force && use_cache && self.restore_artifact(&recipe, &fingerprint)? {
                self.state.successful.insert(recipe.id.clone(), fingerprint);
                self.save()?;
                summary.restored.push(recipe.id);
                continue;
            }
            run(&recipe)?;
            if use_cache {
                self.store_artifact(&recipe, &fingerprint)?;
            }
            self.state.successful.insert(recipe.id.clone(), fingerprint);
            self.save()?;
            summary.ran.push(recipe.id);
        }
        Ok(summary)
    }

    fn restore_artifact(&self, recipe: &Recipe, fingerprint: &str) -> Result<bool> {
        if recipe.outputs.is_empty() || recipe.outputs_ready() {
            return Ok(false);
        }
        let pointer = self.artifact_root.join("inputs").join(fingerprint);
        let hash = match fs::read_to_string(&pointer) {
            Ok(hash) => hash.trim().to_owned(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        if hash.len() != 64
            || !hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            bail!("invalid artifact cache pointer {}", pointer.display());
        }
        let archive = self
            .artifact_root
            .join("objects")
            .join(format!("{hash}.tar"));
        if hash_file(&archive)? != hash {
            bail!("artifact cache object {hash} failed verification");
        }
        let status = Command::new("tar")
            .arg("-xf")
            .arg(&archive)
            .arg("-C")
            .arg(&recipe.working_dir)
            .status()
            .with_context(|| format!("restore cached artifact for {}", recipe.id))?;
        if !status.success() || !recipe.outputs_ready() {
            bail!("restore cached artifact for {} failed", recipe.id);
        }
        Ok(true)
    }

    fn store_artifact(&self, recipe: &Recipe, fingerprint: &str) -> Result<()> {
        if !recipe.outputs_ready() {
            return Ok(());
        }
        let objects = self.artifact_root.join("objects");
        let inputs = self.artifact_root.join("inputs");
        fs::create_dir_all(&objects)?;
        fs::create_dir_all(&inputs)?;
        let temporary = self
            .artifact_root
            .join(format!("artifact-{}.partial", std::process::id()));
        let status = Command::new("tar")
            .arg("-cf")
            .arg(&temporary)
            .arg("-C")
            .arg(&recipe.working_dir)
            .args(recipe.outputs)
            .status()
            .with_context(|| format!("cache artifact for {}", recipe.id))?;
        if !status.success() {
            let _ = fs::remove_file(&temporary);
            bail!("cache artifact for {} failed", recipe.id);
        }
        let hash = hash_file(&temporary)?;
        let object = objects.join(format!("{hash}.tar"));
        if object.exists() {
            fs::remove_file(&temporary)?;
        } else {
            fs::rename(&temporary, &object)?;
        }
        let pointer = inputs.join(fingerprint);
        let pointer_temporary = pointer.with_extension(format!("partial-{}", std::process::id()));
        fs::write(&pointer_temporary, format!("{hash}\n"))?;
        fs::rename(pointer_temporary, pointer)?;
        Ok(())
    }

    fn save(&self) -> Result<()> {
        let parent = self
            .state_path
            .parent()
            .context("hydration state path has no parent")?;
        fs::create_dir_all(parent)?;
        let temporary = self
            .state_path
            .with_extension(format!("tmp-{}", std::process::id()));
        let mut file = fs::File::create(&temporary)?;
        file.write_all(&serde_json::to_vec_pretty(&self.state)?)?;
        file.sync_all()?;
        fs::rename(&temporary, &self.state_path)?;
        Ok(())
    }
}

fn hash_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn detect_recipes(repo: &Path) -> Result<Vec<Recipe>> {
    let classifier = Classifier::load(repo)?;
    let mut recipes = Vec::new();
    let walker = WalkDir::new(repo)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| traversable(entry, repo, &classifier));
    for entry in walker {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let Some(parent) = entry.path().parent() else {
            continue;
        };
        let (kind, program, args, manifest, outputs) = match entry.file_name().to_str() {
            Some("package-lock.json") if parent.join("package.json").is_file() => (
                "npm",
                "npm",
                &["ci"][..],
                parent.join("package.json"),
                &["node_modules"][..],
            ),
            Some("uv.lock") if parent.join("pyproject.toml").is_file() => (
                "uv",
                "uv",
                &["sync", "--frozen"][..],
                parent.join("pyproject.toml"),
                &[".venv"][..],
            ),
            Some("pnpm-lock.yaml") if parent.join("package.json").is_file() => (
                "pnpm",
                "pnpm",
                &["install", "--frozen-lockfile"][..],
                parent.join("package.json"),
                &["node_modules"][..],
            ),
            Some("yarn.lock") if parent.join("package.json").is_file() => (
                "yarn",
                "yarn",
                &["install", "--frozen-lockfile"][..],
                parent.join("package.json"),
                &["node_modules"][..],
            ),
            Some("bun.lock" | "bun.lockb") if parent.join("package.json").is_file() => (
                "bun",
                "bun",
                &["install", "--frozen-lockfile"][..],
                parent.join("package.json"),
                &["node_modules"][..],
            ),
            Some("poetry.lock") if parent.join("pyproject.toml").is_file() => (
                "poetry",
                "poetry",
                &["install", "--no-interaction"][..],
                parent.join("pyproject.toml"),
                &[".venv"][..],
            ),
            Some("Cargo.lock") if parent.join("Cargo.toml").is_file() => (
                "cargo",
                "cargo",
                &["fetch", "--locked"][..],
                parent.join("Cargo.toml"),
                &[][..],
            ),
            Some("go.sum") if parent.join("go.mod").is_file() => (
                "go",
                "go",
                &["mod", "download"][..],
                parent.join("go.mod"),
                &[][..],
            ),
            _ => continue,
        };
        let relative = parent.strip_prefix(repo)?;
        let location = if relative.as_os_str().is_empty() {
            ".".to_owned()
        } else {
            relative.to_string_lossy().replace('\\', "/")
        };
        recipes.push(Recipe {
            id: format!("{kind}:{location}"),
            program,
            args,
            working_dir: parent.to_owned(),
            inputs: vec![manifest, entry.path().to_owned()],
            outputs,
        });
    }
    recipes.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(recipes)
}

fn traversable(entry: &DirEntry, repo: &Path, classifier: &Classifier) -> bool {
    if entry.depth() == 0 || !entry.file_type().is_dir() {
        return true;
    }
    let Ok(relative) = entry.path().strip_prefix(repo) else {
        return false;
    };
    let first = relative.components().next();
    if first == Some(std::path::Component::Normal(".git".as_ref()))
        || first == Some(std::path::Component::Normal(".pando".as_ref()))
    {
        return false;
    }
    classifier.is_portable(relative, true)
}

fn hash_field(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

#[cfg(test)]
mod tests {
    use super::Hydrator;
    use anyhow::{Result, bail};
    use std::cell::Cell;
    use std::fs;

    fn write(path: &std::path::Path, contents: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    #[test]
    fn detects_root_and_nested_recipes_but_skips_derived_trees() {
        let root = tempfile::tempdir().unwrap();
        write(&root.path().join("package.json"), "{}");
        write(&root.path().join("package-lock.json"), "{}");
        write(&root.path().join("services/api/pyproject.toml"), "");
        write(&root.path().join("services/api/uv.lock"), "");
        write(&root.path().join("apps/web/package.json"), "{}");
        write(&root.path().join("apps/web/pnpm-lock.yaml"), "");
        write(&root.path().join("tools/Cargo.toml"), "");
        write(&root.path().join("tools/Cargo.lock"), "");
        write(&root.path().join("node_modules/x/package.json"), "{}");
        write(&root.path().join("node_modules/x/package-lock.json"), "{}");
        write(&root.path().join("target/x/pyproject.toml"), "");
        write(&root.path().join("target/x/uv.lock"), "");

        let hydrator =
            Hydrator::open_with_state(root.path(), root.path().join("state.json")).unwrap();
        let recipes = hydrator.recipes().unwrap();
        let ids: Vec<_> = recipes.iter().map(|recipe| recipe.id()).collect();

        assert_eq!(
            ids,
            ["cargo:tools", "npm:.", "pnpm:apps/web", "uv:services/api"]
        );
        assert_eq!(recipes[0].program(), "cargo");
        assert_eq!(recipes[0].args(), ["fetch", "--locked"]);
        assert_eq!(recipes[1].program(), "npm");
        assert_eq!(recipes[1].args(), ["ci"]);
        assert_eq!(recipes[2].program(), "pnpm");
        assert_eq!(recipes[2].args(), ["install", "--frozen-lockfile"]);
        assert_eq!(recipes[3].program(), "uv");
        assert_eq!(recipes[3].args(), ["sync", "--frozen"]);
    }

    #[test]
    fn unchanged_inputs_are_skipped_and_lockfile_changes_rerun() {
        let root = tempfile::tempdir().unwrap();
        write(&root.path().join("package.json"), "{}");
        write(&root.path().join("package-lock.json"), "one");
        let state = root.path().join("state/state.json");
        let mut hydrator = Hydrator::open_with_state(root.path(), state).unwrap();
        let runs = Cell::new(0);

        let first = hydrator
            .run_changed_with(false, |_| {
                runs.set(runs.get() + 1);
                Ok(())
            })
            .unwrap();
        let second = hydrator
            .run_changed_with(false, |_| {
                runs.set(runs.get() + 1);
                Ok(())
            })
            .unwrap();
        write(&root.path().join("package-lock.json"), "two");
        let third = hydrator
            .run_changed_with(false, |_| {
                runs.set(runs.get() + 1);
                Ok(())
            })
            .unwrap();

        assert_eq!(runs.get(), 2);
        assert_eq!(first.ran, ["npm:."]);
        assert_eq!(second.skipped, ["npm:."]);
        assert_eq!(third.ran, ["npm:."]);
    }

    #[test]
    fn failed_recipe_is_retried() {
        let root = tempfile::tempdir().unwrap();
        write(&root.path().join("pyproject.toml"), "");
        write(&root.path().join("uv.lock"), "");
        let mut hydrator =
            Hydrator::open_with_state(root.path(), root.path().join("state/state.json")).unwrap();
        let attempts = Cell::new(0);

        let failed = hydrator.run_changed_with(false, |_| -> Result<()> {
            attempts.set(attempts.get() + 1);
            bail!("simulated failure")
        });
        assert!(failed.is_err());
        let retried = hydrator
            .run_changed_with(false, |_| {
                attempts.set(attempts.get() + 1);
                Ok(())
            })
            .unwrap();

        assert_eq!(attempts.get(), 2);
        assert_eq!(retried.ran, ["uv:."]);
    }

    #[test]
    fn force_reruns_successful_recipes() {
        let root = tempfile::tempdir().unwrap();
        write(&root.path().join("package.json"), "{}");
        write(&root.path().join("package-lock.json"), "{}");
        let mut hydrator =
            Hydrator::open_with_state(root.path(), root.path().join("state/state.json")).unwrap();
        hydrator.run_changed_with(false, |_| Ok(())).unwrap();

        let forced = hydrator.run_changed_with(true, |_| Ok(())).unwrap();

        assert_eq!(forced.ran, ["npm:."]);
        assert!(forced.skipped.is_empty());
    }

    #[test]
    fn verified_platform_cache_restores_missing_derived_outputs() {
        let root = tempfile::tempdir().unwrap();
        write(&root.path().join("package.json"), "{}");
        write(&root.path().join("package-lock.json"), "{}");
        let mut hydrator =
            Hydrator::open_with_state(root.path(), root.path().join("state/state.json")).unwrap();
        hydrator.artifact_root = root.path().join("artifact-cache");

        let first = hydrator
            .run_changed_with_cache(false, true, |recipe| {
                write(
                    &recipe.working_dir().join("node_modules/pkg/index.js"),
                    "cached output",
                );
                Ok(())
            })
            .unwrap();
        assert_eq!(first.ran, ["npm:."]);
        fs::remove_dir_all(root.path().join("node_modules")).unwrap();

        let restored = hydrator
            .run_changed_with_cache(false, true, |_| bail!("recipe should not run"))
            .unwrap();
        assert_eq!(restored.restored, ["npm:."]);
        assert_eq!(
            fs::read_to_string(root.path().join("node_modules/pkg/index.js")).unwrap(),
            "cached output"
        );

        fs::remove_dir_all(root.path().join("node_modules")).unwrap();
        let object = fs::read_dir(root.path().join("artifact-cache/objects"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        fs::write(object, "tampered").unwrap();
        let error = hydrator
            .run_changed_with_cache(false, true, |_| bail!("recipe should not run"))
            .unwrap_err();
        assert!(error.to_string().contains("failed verification"));
    }
}
