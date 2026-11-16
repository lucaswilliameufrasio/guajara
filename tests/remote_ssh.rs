use guajara::remote::Client;
use std::fs;
use std::io::Write;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Server {
    child: Child,
    directory: tempfile::TempDir,
    config: PathBuf,
    remote_home: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn generate_key(path: &Path) {
    let output = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(path)
        .output()
        .unwrap();
    assert!(output.status.success(), "Test key generation failed");
}

impl Server {
    fn start() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let remote_home = directory.path().join("remote home");
        fs::create_dir(&remote_home).unwrap();
        let host_key = directory.path().join("host-key");
        let client_key = directory.path().join("client-key");
        generate_key(&host_key);
        generate_key(&client_key);
        let authorized_keys = directory.path().join("authorized_keys");
        fs::copy(client_key.with_extension("pub"), &authorized_keys).unwrap();
        // Use the real ssh-keygen but supply an empty test-only passphrase. This
        // avoids interactive input in CI without changing the production adapter.
        let binaries = directory.path().join("bin");
        fs::create_dir(&binaries).unwrap();
        let key_generator = binaries.join("ssh-keygen");
        let real_key_generator = Command::new("sh")
            .args(["-c", "command -v ssh-keygen"])
            .output()
            .unwrap();
        let real_key_generator = String::from_utf8(real_key_generator.stdout).unwrap();
        fs::write(
            &key_generator,
            format!(
                "#!/bin/sh\nexec {} -N '' \"$@\"\n",
                guajara::remote::shell_quote(real_key_generator.trim())
            ),
        )
        .unwrap();
        fs::set_permissions(&key_generator, fs::Permissions::from_mode(0o755)).unwrap();
        let wrapper = directory.path().join("remote-shell");
        fs::write(&wrapper, format!("#!/bin/sh\nexport HOME={}\nexport PATH={}:\"$PATH\"\nexec sh -c \"$SSH_ORIGINAL_COMMAND\"\n", guajara::remote::shell_quote(remote_home.to_str().unwrap()), guajara::remote::shell_quote(binaries.to_str().unwrap()))).unwrap();
        fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let daemon_config = directory.path().join("sshd_config");
        fs::write(&daemon_config, format!("Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nPidFile {}\nAuthorizedKeysFile {}\nStrictModes no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nForceCommand {}\nLogLevel ERROR\n", host_key.display(), directory.path().join("sshd.pid").display(), authorized_keys.display(), wrapper.display())).unwrap();
        let daemon_log = directory.path().join("sshd.log");
        let mut child = Command::new("/usr/sbin/sshd")
            .arg("-D")
            .arg("-e")
            .arg("-f")
            .arg(&daemon_config)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(fs::File::create(&daemon_log).unwrap())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                panic!(
                    "Isolated sshd could not start ({status}): {}",
                    fs::read_to_string(&daemon_log).unwrap()
                );
            }
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "Isolated sshd did not become ready"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        let public_host_key = fs::read_to_string(host_key.with_extension("pub")).unwrap();
        let known_hosts = directory.path().join("known_hosts");
        fs::write(
            &known_hosts,
            format!("[127.0.0.1]:{port} {public_host_key}"),
        )
        .unwrap();
        let username = Command::new("id").arg("-un").output().unwrap();
        let username = String::from_utf8(username.stdout).unwrap();
        let config = directory.path().join("client_config");
        fs::write(&config, format!("Host fixture\n HostName 127.0.0.1\n Port {port}\n User {}\n IdentityFile {}\n IdentitiesOnly yes\n BatchMode yes\n StrictHostKeyChecking yes\n UserKnownHostsFile {}\n", username.trim(), client_key.display(), known_hosts.display())).unwrap();
        Self {
            child,
            directory,
            config,
            remote_home,
        }
    }
}

#[test]
fn should_manage_copy_and_create_keys_over_real_isolated_ssh_without_python() {
    let server = Server::start();
    let client = Client::new(&server.config, "fixture").unwrap();
    let missing = client.read().unwrap();
    assert!(!missing.exists);
    assert!(client.keys().unwrap().is_empty());
    let initial = "# remote comment\nHost existing\n    User alice\n";
    client.write(&missing, initial).unwrap();
    let original = client.read().unwrap();
    assert_eq!(original.content, initial);
    let remote_key = client.create_key("id_remote_test").unwrap();
    assert_eq!(remote_key, PathBuf::from("~/.ssh/id_remote_test"));
    assert!(server.remote_home.join(".ssh/id_remote_test").is_file());
    let public_key = client.public_key("~/.ssh/id_remote_test").unwrap();
    assert!(public_key.starts_with("ssh-ed25519 "));
    assert!(client.public_key("relative").is_err());
    assert_eq!(
        guajara::remote::install_public_key(&server.config, "fixture", &public_key).unwrap(),
        guajara::remote::KeyAuthorization::Installed
    );
    let installed = fs::read_to_string(server.remote_home.join(".ssh/authorized_keys")).unwrap();
    assert_eq!(installed.trim(), public_key.trim());
    assert_eq!(
        guajara::remote::install_public_key(&server.config, "fixture", &public_key).unwrap(),
        guajara::remote::KeyAuthorization::AlreadyPresent
    );
    assert_eq!(
        fs::read_to_string(server.remote_home.join(".ssh/authorized_keys")).unwrap(),
        installed
    );
    let mut key_parts = public_key.split_whitespace();
    let same_key_new_comment = format!(
        "{} {} different-comment\n",
        key_parts.next().unwrap(),
        key_parts.next().unwrap()
    );
    assert_eq!(
        guajara::remote::install_public_key(&server.config, "fixture", &same_key_new_comment)
            .unwrap(),
        guajara::remote::KeyAuthorization::AlreadyPresent
    );
    assert_eq!(
        fs::read_to_string(server.remote_home.join(".ssh/authorized_keys")).unwrap(),
        installed
    );
    let authorized = server.remote_home.join(".ssh/authorized_keys");
    let backup = server.remote_home.join(".ssh/authorized_keys.backup");
    fs::rename(&authorized, &backup).unwrap();
    std::os::unix::fs::symlink(&backup, &authorized).unwrap();
    assert!(guajara::remote::install_public_key(&server.config, "fixture", &public_key).is_err());
    assert_eq!(fs::read_to_string(&backup).unwrap(), installed);
    fs::remove_file(&authorized).unwrap();
    fs::rename(&backup, &authorized).unwrap();
    let rsa_key = client
        .create_key_with_algorithm("id_rsa_test", guajara::identity::KeyAlgorithm::Rsa4096)
        .unwrap();
    assert_eq!(rsa_key, PathBuf::from("~/.ssh/id_rsa_test"));
    let fingerprint = Command::new("ssh-keygen")
        .arg("-lf")
        .arg(server.remote_home.join(".ssh/id_rsa_test.pub"))
        .output()
        .unwrap();
    assert!(fingerprint.status.success());
    assert!(String::from_utf8_lossy(&fingerprint.stdout).contains("4096"));
    let keys = client.keys().unwrap();
    assert_eq!(
        keys,
        vec![
            server.remote_home.join(".ssh/id_remote_test"),
            server.remote_home.join(".ssh/id_rsa_test")
        ]
    );
    assert!(client.create_key("id_remote_test").is_err());
    let source = guajara::SshConfig::parse(
        "Host first\n HostName first.example\n IdentityFile /local/private\nHost second\n HostName second.example\n IdentityFile /local/other\n",
    );
    let destination = guajara::SshConfig::parse(&original.content);
    let copied = guajara::remote::copy_hosts(
        &source,
        &[
            (0, Some(keys[0].to_str().unwrap().into())),
            (1, Some("~/.ssh/id_remote_test".into())),
        ],
        &destination,
    )
    .unwrap();
    client.write(&original, &copied.to_string()).unwrap();
    let final_snapshot = client.read().unwrap();
    assert!(final_snapshot.content.starts_with(initial));
    assert_eq!(
        guajara::SshConfig::parse(&final_snapshot.content)
            .hosts()
            .len(),
        3
    );
    assert!(!final_snapshot.content.contains("/local/"));
    assert!(client.write(&original, "Host stale\n").is_err());
    assert_eq!(client.read().unwrap().content, final_snapshot.content);
    assert!(!server.directory.path().join("id_remote_test").exists());
    let remote_public_key = fs::read(server.remote_home.join(".ssh/id_remote_test.pub")).unwrap();
    fs::OpenOptions::new()
        .append(true)
        .open(server.directory.path().join("authorized_keys"))
        .unwrap()
        .write_all(&remote_public_key)
        .unwrap();
    let local_transport_config = fs::read_to_string(&server.config).unwrap();
    let loopback_config = local_transport_config
        .lines()
        .filter(|line| !line.trim_start().starts_with("IdentityFile "))
        .collect::<Vec<_>>()
        .join("\n")
        .replace("Host fixture", "Host loopback");
    let updated = format!(
        "{}\n{loopback_config}\n IdentityFile {}\n",
        final_snapshot.content,
        guajara::remote::config_path(keys[0].to_str().unwrap())
    );
    client.write(&final_snapshot, &updated).unwrap();
    client.test_host("loopback").unwrap();
}

#[test]
fn openssh_local_command_runs_only_after_successful_authentication() {
    let server = Server::start();
    let marker = server.directory.path().join("local-command-events");
    let base = fs::read_to_string(&server.config).unwrap();
    let config = server.directory.path().join("hook_config");
    fs::write(
        &config,
        format!(
            "{base}\n PermitLocalCommand yes\n LocalCommand printf 'connected\\n' >> {}\n",
            guajara::remote::shell_quote(marker.to_str().unwrap())
        ),
    )
    .unwrap();
    let status = Command::new("ssh")
        .arg("-F")
        .arg(&config)
        .args(["-T", "fixture", "true"])
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(fs::read_to_string(&marker).unwrap(), "connected\n");

    let wrong_key = server.directory.path().join("wrong-key");
    generate_key(&wrong_key);
    let denied_config = server.directory.path().join("denied_config");
    let denied = base
        .lines()
        .filter(|line| !line.trim_start().starts_with("IdentityFile "))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(
        &denied_config,
        format!(
            "{denied}\n IdentityFile {}\n PermitLocalCommand yes\n LocalCommand printf 'unexpected\\n' >> {}\n",
            wrong_key.display(),
            guajara::remote::shell_quote(marker.to_str().unwrap())
        ),
    )
    .unwrap();
    let status = Command::new("ssh")
        .arg("-F")
        .arg(&denied_config)
        .args(["-T", "fixture", "true"])
        .status()
        .unwrap();
    assert!(!status.success());
    assert_eq!(fs::read_to_string(&marker).unwrap(), "connected\n");
}

#[test]
fn opt_in_hook_records_a_real_successful_ssh_connection() {
    let server = Server::start();
    let home = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_guajara"))
        .env("HOME", home.path())
        .arg("--ssh-config")
        .arg(&server.config)
        .args(["--yes", "ssh", "enable-usage", "fixture"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let usage_dir = home.path().join(".config/guajara/ssh-use");
    guajara::ssh_usage::record_use(&usage_dir, "older").unwrap();
    let status = Command::new("ssh")
        .env("HOME", home.path())
        .arg("-F")
        .arg(&server.config)
        .args(["-T", "fixture", "true"])
        .status()
        .unwrap();
    assert!(status.success());
    let usage = guajara::ssh_usage::load_usage(&usage_dir);
    assert!(usage.contains_key("fixture"));
    let legacy = std::collections::HashMap::new();
    assert!(
        guajara::ssh_usage::last_used_millis("fixture", &legacy, &usage)
            > guajara::ssh_usage::last_used_millis("older", &legacy, &usage)
    );
}
