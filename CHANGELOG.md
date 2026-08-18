# Changelog

[English](./CHANGELOG.md) | [简体中文](./CHANGELOG.zh-CN.md)

## 0.3.7 — 2026-08-18

### Docs
- README (EN/ZH): explicit **Credits / prior art** — product shape informed by open-source [LiveAgent](https://github.com/thirsty5034/LiveAgent); DSH-native reimplementation, not a fork  

## 0.3.6 — 2026-08-16

### Community packaging
- Public GitHub repo layout aligned with dsh-better-sidebar  
- `scripts/install.sh` / `install.ps1` (GitHub default; `--from npm` ready)  
- package.json: `repository` / `homepage` / `bugs` / `publishConfig`  

### Docs
- Add Simplified Chinese README / CHANGELOG alongside English

## 0.3.5 — 2026-08-16

### Added
- Client i18n following dsh-better-sidebar: `ctx.locale.register("sshTunnel", zh|en)`, `t(key)`, live switch via `useSyncExternalStore`

### Fixed
- Plugin load TDZ when `zh.footerHint` incorrectly called `t()` during dictionary init

## 0.3.4 — 2026-08-16

### Changed
- Publish prep: package metadata, MIT LICENSE, README, CHANGELOG
- Extract shared pure modules (`lib/shared/*`) with offline smoke tests
- `shellRead` returns incremental `chunk` by default (omit full buffer unless `full: true`)
- Theme-safe UI tokens; in-panel dialogs for SFTP prompts (0.3.x)
- Neutral package description (no third-party product marketing)

### Fixed
- Host library delete asks for confirmation again
- Style sheet cache bust when CSS updates

## 0.3.0 — 2026-08-16

- Center overlay terminal (xterm) and dual-pane SFTP
- Project-scoped grants, SSHManager tool, OpenSSH scan

## 0.1.0 — 2026-08-16

- Initial permanent plugin scaffold
