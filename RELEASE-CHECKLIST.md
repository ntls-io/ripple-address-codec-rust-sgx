# Release Checklist

- [ ] Update the `HISTORY.md`
- [ ] Update the version in `Cargo.toml`
- [ ] Update the version in `html_root_url` (`src/lib.rs`)
- [ ] Run `rustup update`
- [ ] Run `cargo fmt`
- [ ] Run `cargo update`
- [ ] Run `cargo test`
- [ ] Run `cargo doc`
- [ ] Git: `git commit -a -m ""`
- [ ] Git: `git push origin master`
- [ ] CI: wait success or repeat...
- [ ] Git: add version annotated tag `git tag -a vX.Y.Z`
- [ ] Git: push tags `git push origin vX.Y.Z`
- [ ] Run `cargo publish`
