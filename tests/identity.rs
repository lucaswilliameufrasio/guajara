use guajara::identity::{discover, generate, new_key_path};
use std::fs;
use std::process::Command;

#[test]
fn should_discover_real_openssh_keys_and_ignore_other_files() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("id_test");
    let result = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(result.status.success());
    fs::write(directory.path().join("config"), "Host example\n").unwrap();
    fs::write(directory.path().join("known_hosts"), "fixture").unwrap();
    fs::write(
        directory.path().join("bad\nname"),
        "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture",
    )
    .unwrap();
    fs::create_dir(directory.path().join("subdirectory")).unwrap();
    assert_eq!(discover(directory.path()).unwrap(), vec![path.clone()]);
    assert!(generate(directory.path(), "id_test").is_err());
    assert!(path.is_file());
    assert!(directory.path().join("id_test.pub").is_file());
}

#[test]
fn should_handle_missing_directory_and_reject_non_directory() {
    let directory = tempfile::tempdir().unwrap();
    assert!(
        discover(&directory.path().join("missing"))
            .unwrap()
            .is_empty()
    );
    let file = directory.path().join("file");
    fs::write(&file, "fixture").unwrap();
    assert!(discover(&file).is_err());
}

#[test]
fn should_sort_pem_keys_and_validate_names_without_overwriting_files() {
    let directory = tempfile::tempdir().unwrap();
    for name in ["z_key", "a_key"] {
        fs::write(
            directory.path().join(name),
            "-----BEGIN RSA PRIVATE KEY-----\nfixture",
        )
        .unwrap();
    }
    assert_eq!(
        discover(directory.path()).unwrap(),
        vec![
            directory.path().join("a_key"),
            directory.path().join("z_key")
        ]
    );
    for name in [
        "",
        "../escape",
        "/absolute",
        ".hidden",
        "key.pub",
        "two words",
        "-N secret",
    ] {
        assert!(new_key_path(directory.path(), name).is_err());
    }
    assert!(new_key_path(directory.path(), "a_key").is_err());
    fs::write(directory.path().join("public_only.pub"), "fixture").unwrap();
    assert!(new_key_path(directory.path(), "public_only").is_err());
    std::os::unix::fs::symlink("missing", directory.path().join("dangling")).unwrap();
    assert!(new_key_path(directory.path(), "dangling").is_err());
    assert_eq!(
        new_key_path(directory.path(), "id_new-1").unwrap(),
        directory.path().join("id_new-1")
    );
}
