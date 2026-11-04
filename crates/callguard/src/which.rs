//! Finding a program by its bare name. On Windows a name is looked up on `PATH`
//! with the extensions of `PATHEXT`, so `judge.cmd` works as `judge`. The
//! current directory is searched only if `PATH` lists it: a repository must
//! not be able to plant `git.bat`. Other systems leave the name to the OS.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// What to pass to `Command::new` for `name`.
pub fn program(name: &str) -> OsString {
    if cfg!(windows) {
        let path = std::env::var("PATH").unwrap_or_default();
        let pathext = std::env::var("PATHEXT").unwrap_or_default();
        if let Some(found) = find_with(name, &path, &pathext, &|p| p.is_file()) {
            return found.into_os_string();
        }
    }
    name.into()
}

/// The first file on `path` named `name`, trying the `pathext` extensions
/// (`.COM;.EXE;...`) unless `name` already ends in one. None for a name with a
/// directory part (those are not looked up) or when nothing exists.
pub(crate) fn find_with(
    name: &str,
    path: &str,
    pathext: &str,
    is_file: &dyn Fn(&Path) -> bool,
) -> Option<PathBuf> {
    if name.is_empty() || name.contains(['/', '\\', ':']) {
        return None;
    }
    let exts: Vec<&str> = pathext.split(';').filter(|e| e.starts_with('.')).collect();
    let lower = name.to_ascii_lowercase();
    let has_ext = exts
        .iter()
        .any(|e| lower.ends_with(&e.to_ascii_lowercase()));
    let mut candidates = Vec::new();
    if has_ext {
        candidates.push(name.to_owned());
    } else {
        candidates.extend(exts.iter().map(|e| format!("{name}{e}")));
    }
    for dir in path.split(';').filter(|d| !d.is_empty()) {
        for c in &candidates {
            let p = Path::new(dir.trim_matches('"')).join(c);
            if is_file(&p) {
                return Some(p);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXT: &str = ".COM;.EXE;.BAT;.CMD";

    /// A file system holding `(dir, file)` pairs; paths are joined the way the
    /// platform joins them.
    fn files<'a>(list: &'a [(&'a str, &'a str)]) -> impl Fn(&Path) -> bool + 'a {
        // Windows file names are case-insensitive.
        move |p| {
            let lower = |p: &Path| p.to_string_lossy().to_lowercase();
            list.iter()
                .any(|(d, f)| lower(&Path::new(d).join(f)) == lower(p))
        }
    }

    fn at(dir: &str, file: &str) -> Option<PathBuf> {
        Some(Path::new(dir).join(file))
    }

    /// The result as lower-case text (Windows file names ignore case).
    fn low(p: Option<PathBuf>) -> Option<String> {
        p.map(|p| p.to_string_lossy().to_lowercase())
    }

    #[test]
    fn a_bare_name_gets_the_first_extension_that_exists_on_path() {
        let on_disk = files(&[("C:tools", "judge.cmd"), ("C:other", "judge.exe")]);
        let got = find_with("judge", "C:bin;C:tools;C:other", EXT, &on_disk);
        assert_eq!(low(got), low(at("C:tools", "judge.cmd")));
        let got = find_with("judge", "C:other;C:tools", EXT, &on_disk);
        assert_eq!(low(got), low(at("C:other", "judge.exe")));
    }

    #[test]
    fn a_name_with_a_known_extension_is_taken_as_it_is() {
        let on_disk = files(&[("bin", "Judge.CMD")]);
        let got = find_with("Judge.CMD", "bin", EXT, &on_disk);
        assert_eq!(got, at("bin", "Judge.CMD"));
    }

    #[test]
    fn the_current_directory_is_searched_only_if_path_lists_it() {
        let on_disk = files(&[("", "git.bat"), (".", "git.bat")]);
        assert_eq!(find_with("git", "bin;;", EXT, &on_disk), None);
        assert_eq!(find_with("git", "", EXT, &on_disk), None);
        let got = find_with("git", "bin;.", EXT, &on_disk);
        assert_eq!(low(got), low(at(".", "git.bat")));
    }

    #[test]
    fn names_with_a_directory_part_are_not_looked_up() {
        let on_disk = files(&[("bin", "judge.cmd")]);
        assert_eq!(find_with("sub\\judge", "bin", EXT, &on_disk), None);
        assert_eq!(find_with("sub/judge", "bin", EXT, &on_disk), None);
        assert_eq!(find_with("C:judge", "bin", EXT, &on_disk), None);
    }
}
