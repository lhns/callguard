use std::io::Cursor;

use super::*;

fn rules(r: &[&str]) -> Vec<String> {
    r.iter().map(|s| (*s).to_owned()).collect()
}

fn record(d: &tempfile::TempDir) -> PathBuf {
    record_path(&UserConfig::Dir(
        d.path().join("cfg").to_string_lossy().into_owned(),
    ))
    .unwrap()
}

#[test]
fn the_hash_is_stable_and_follows_rules_order_and_place() {
    let a = rules_hash("/p", &rules(&["Bash(ls)", "Bash(git log *)"]));
    assert_eq!(
        a,
        rules_hash("/p", &rules(&["Bash(ls)", "Bash(git log *)"]))
    );
    assert_eq!(a.len(), 64);
    assert_ne!(
        a,
        rules_hash("/p", &rules(&["Bash(git log *)", "Bash(ls)"])),
        "order"
    );
    assert_ne!(
        a,
        rules_hash("/p", &rules(&["Bash(ls)", "Bash(git log -5)"])),
        "a rule"
    );
    assert_ne!(
        a,
        rules_hash("/q", &rules(&["Bash(ls)", "Bash(git log *)"])),
        "place"
    );
    assert_ne!(a, rules_hash("/p", &rules(&["Bash(ls)"])), "fewer rules");
    // A rule cannot borrow from its neighbour.
    assert_ne!(
        rules_hash("/p", &rules(&["a", "b"])),
        rules_hash("/p", &rules(&["a\nb"]))
    );
}

#[test]
fn trust_follows_the_record() {
    let d = tempfile::tempdir().unwrap();
    let path = record(&d);
    let allow = rules(&["Bash(git log *)"]);
    assert_eq!(load(&path), Record::Missing);
    write_entry(&path, "/p", &allow).unwrap();
    let Record::Entries(e) = load(&path) else {
        panic!()
    };
    assert_eq!(e.len(), 1);
    assert_eq!(state(&e, "/p", &allow), State::Trusted);
    assert_eq!(
        state(&e, "/p", &rules(&["Bash(git log -5)"])),
        State::Changed
    );
    assert_eq!(
        state(&e, "/moved", &allow),
        State::Untrusted,
        "a moved project is a new one"
    );
    // Trusting again replaces; another project adds.
    write_entry(&path, "/p", &rules(&["Bash(ls)"])).unwrap();
    write_entry(&path, "/other", &allow).unwrap();
    let Record::Entries(e) = load(&path) else {
        panic!()
    };
    assert_eq!(e.len(), 2);
    assert_eq!(state(&e, "/p", &allow), State::Changed);
    assert!(revoke(&path, "/p").unwrap());
    assert!(!revoke(&path, "/p").unwrap());
    let Record::Entries(e) = load(&path) else {
        panic!()
    };
    assert_eq!(e.len(), 1);
}

#[test]
fn a_malformed_or_unreadable_record_trusts_nothing() {
    let d = tempfile::tempdir().unwrap();
    let path = record(&d);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    for bad in ["not json", "{}", "[1,2]", "{\"project\":\"/p\"}"] {
        std::fs::write(&path, bad).unwrap();
        assert!(matches!(load(&path), Record::Unreadable(_)), "{bad}");
    }
    let cfg = UserConfig::Dir(d.path().join("cfg").to_string_lossy().into_owned());
    let w = check_for_load(&cfg, "/p", &rules(&["Bash(ls)"])).unwrap_err();
    assert!(w.contains("not trusted") && w.contains("unreadable"), "{w}");
    // Writing over a bad file repairs it.
    write_entry(&path, "/p", &rules(&["Bash(ls)"])).unwrap();
    assert!(matches!(load(&path), Record::Entries(_)));
}

#[test]
fn the_write_is_atomic_and_leaves_no_temporary_file() {
    let d = tempfile::tempdir().unwrap();
    let path = record(&d);
    write_entry(&path, "/p", &rules(&["Bash(ls)"])).unwrap();
    write_entry(&path, "/q", &rules(&["Bash(ls)"])).unwrap();
    let names: Vec<String> = std::fs::read_dir(path.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, [FILE], "{names:?}");
}

#[test]
fn the_load_check_words_its_warning() {
    let d = tempfile::tempdir().unwrap();
    let cfg = UserConfig::Dir(d.path().join("cfg").to_string_lossy().into_owned());
    let proj = d.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let p = proj.to_string_lossy().into_owned();
    let allow = rules(&["Bash(git log *)", "Bash(ls)"]);
    let w = check_for_load(&cfg, &p, &allow).unwrap_err();
    assert!(
        w.contains("2 rules") && w.contains("not trusted") && w.contains("callguard trust"),
        "{w}"
    );
    write_entry(&record_path(&cfg).unwrap(), &canonical(&p), &allow).unwrap();
    assert!(check_for_load(&cfg, &p, &allow).is_ok());
    let w = check_for_load(&cfg, &p, &allow[..1]).unwrap_err();
    assert!(w.contains("changed since"), "{w}");
    // The user layer is skipped: nothing can be trusted.
    assert!(check_for_load(&UserConfig::None, &p, &allow).is_err());
}

#[test]
fn confirm_takes_only_y_or_yes() {
    for (a, want) in [
        ("y\n", true),
        ("Y", true),
        (" yes \n", true),
        ("YES\r\n", true),
        ("n\n", false),
        ("\n", false),
        ("ye\n", false),
        ("sure\n", false),
        ("", false),
    ] {
        let mut out = Vec::new();
        assert_eq!(confirm(&mut Cursor::new(a), &mut out), want, "{a:?}");
        assert_eq!(String::from_utf8(out).unwrap(), "Trust these rules? [y/N] ");
    }
}

/// A backslash is a letter in a Unix directory name, not a separator.
#[cfg(unix)]
#[test]
fn a_backslash_name_is_not_the_nested_directory() {
    assert_ne!(canonical(r"/a\b"), canonical("/a/b"));
}
