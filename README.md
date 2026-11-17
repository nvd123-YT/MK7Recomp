# Mario Kart 7 Recompiled

<a href="https://recomplauncher.com/game/mk7recomp"><picture><source media="(prefers-color-scheme: dark)" srcset="https://recomplauncher.com/assets/press/launcher/badge-light.svg"><img alt="Get it on RecompLauncher" src="https://recomplauncher.com/assets/press/launcher/badge-dark.svg" height="48"></picture></a>

A game-specific desktop build based on [Zakuro](https://github.com/fearkov/zakuro), a high-level-emulation Nintendo 3DS runtime, and [3dsrecomp](https://github.com/fearkov/3dsrecomp), its ahead-of-time ARM code recompiler.

This fork is deliberately limited to **Mario Kart 7 for Nintendo 3DS**. Other games are hidden from the library and cannot be launched through the application.

## Supported game dumps

| Region | Nintendo 3DS title ID |
|---|---|
| Japan | 0004000000030600 |
| Europe | 0004000000030700 |
| USA | 0004000000030800 |
| Korea | 0004000000030A00 |
| Taiwan | 000400000008B400 |
| China | 000400000008B500 |

The application expects a legally obtained, decrypted dump of the game. It does not include the ROM, game code, textures, music, or other game assets.

## Version 1.0.4 changes

- Returns decompressed executable bytes for NCCH Code archive requests, matching the image mapped into game memory and avoiding checksum mismatches on compressed `.code` files.

## Version 1.0.3 changes

- Keeps encrypted or damaged Mario Kart 7 CIA dumps visible in the library with an explanatory warning instead of silently hiding them.

## Version 1.0.2 changes

- Adds RecompLauncher setup and direct game launching on Windows, Linux and macOS, with the manifest shipped in every release package.
- Adds `--game <path>` while keeping positional game paths, plus windowless `--prepare` and borderless `--fullscreen` support.
- Adds launcher-editable graphics, display, emulation and sound settings, with Big Picture mode starting fullscreen.
- Declares game save archives, extra data, system saves, save states, cheats and launcher settings for RecompLauncher backups and cloud saves.
- Uses a lower 2× default 3D rendering resolution to reduce GPU load; higher resolutions remain available.

## Version 1.0.1 changes

- Adds a 3GX startup loader with checked plugin parsing, title and compatibility checks, plugin executable/heap mapping, ARM bootloader handoff, and cleanup when the game exits.
- Implements plg:ldr service commands used by normal plugin loading and discovers Luma and CTGP-7 plugin paths from the emulated SD card.
- Adds GSP framebuffer address translation for the 3GX plugin framebuffer range.
- Adds CSND PCM8, PCM16, and IMA-ADPCM playback, command-list handling, and service-session resource cleanup.
- Preserves compatibility with 1.0.0 save-state data.
- CTGP-7 support is experimental and may or may not work. PSG/noise synthesis, CSND capture DMA, and external SetLoadExeParam injection are not implemented; the loader currently requires an embedded executable-check function.

## Regional update data and CTGP-7

Place an update `.cia` beside its matching base-game dump in the same library folder. The launcher recognizes update title IDs in the `0004000E` namespace by their regional suffix, attaches the update to the matching base game, and selects the highest installed update version. The CTGP-7 v1.2 update title IDs are:

| Region | Mario Kart 7 update title ID | Update version |
|---|---|---:|
| Japan | `0004000E00030600` | 3152 |
| Europe | `0004000E00030700` | 3152 |
| USA | `0004000E00030800` | 3152 |
| Korea | `0004000E00030A00` | 3088 |

**CTGP-7 support is experimental and may or may not work.** The 3GX loader is integrated, but CTGP-7 has not been validated end-to-end. The runtime has a startup bootloader, plugin memory mapping, title compatibility checks, the `plg:ldr` service, and a CSND software mixer for PCM8, PCM16, and IMA-ADPCM. PSG/noise synthesis and CSND capture DMA are not implemented. Plugins must contain an embedded executable-check function; external `SetLoadExeParam` injection is not supported yet.

For a title-specific plugin, place the `.3gx` file in the emulated SD-card folder `user/sdmc/luma/plugins/<16-digit-title-id>/` inside the application's configured data directory. The runtime also accepts `user/sdmc/plugins/<16-digit-title-id>/` and the older top-level `luma/plugins/<16-digit-title-id>/` or `plugins/<16-digit-title-id>/` layouts. For Mario Kart 7 USA, use title ID `0004000000030800`. A fallback plugin can be placed at `user/sdmc/luma/plugins/default.3gx` or `user/sdmc/plugins/default.3gx`. The CTGP-7 plugin path `user/sdmc/CTGP-7/resources/CTGP-7.3gx` is also searched automatically. Put the complete extracted `CTGP-7` folder in the `user/sdmc` folder inside the application's data directory; `user/sdmc` is the emulator's guest-visible SD-card root, so the plugin and its additional resources are both visible. The plugin is mapped before the game's main thread starts.

The CTGP-7 plugin has not yet been run end-to-end in this build. Its launcher flow, plugin dependencies, sound behavior, and gameplay still need validation against the real CTGP-7 plugin and matching v1.2 update on macOS.

## Playing

1. Download the package for your operating system from [Releases](https://github.com/nvd123-YT/MK7Recomp/releases).
2. Extract the download and start Mario Kart 7 Recompiled.
3. Choose the folder containing your decrypted Mario Kart 7 dump. RecompLauncher can instead set up from the dump file directly.
4. Select the game and press **Recompile**. The ARM code is recompiled locally on your computer. This is a one-time step for each game dump/build; recompile again when the runtime reports the installed code is outdated.
5. Start the game. The application uses the local recompiled code where available and falls back to its interpreter for code that is not covered.

The title-specific recompiled output stays on the user's computer. It is not included in this repository, CI artifacts, or GitHub Releases.

## RecompLauncher

Mario Kart 7 Recompiled is listed on [RecompLauncher](https://recomplauncher.com/game/mk7recomp). It accepts your decrypted `.3ds`, `.cci`, `.cxi` or `.cia` dump, runs the local preparation step, and launches the game without opening the normal library window. The launcher exposes supported graphics, display, emulation and audio settings. It also backs up the game's save archives, extra data, system save data, save states, cheats and settings. RecompLauncher keeps the newest ten local backups and offers cloud saves to signed-in players; individual files larger than 64 MB are not backed up by its save service.

The launcher starts in fullscreen automatically in Big Picture mode. The normal desktop default remains windowed; choose Fullscreen in the launcher's Window mode setting to change it.

## Included runtime features

This fork keeps the underlying Zakuro runtime and focuses it on Mario Kart 7:

- Ahead-of-time code recompilation through 3dsrecomp, with interpreter fallback.
- Keyboard, mouse/touchscreen, and common game-controller input.
- Configurable key and controller mappings.
- 3DS screen layouts, scaling, and graphics settings.
- Audio and per-game settings.
- Local save data stored separately under the Mario Kart 7 application-data directory.

Features inherited from the runtime remain subject to the support and behaviour of this particular game.

## Downloads

- **Windows:** unzip mario-kart-7-windows-x86_64.zip and run mario-kart-7.exe.
- **macOS Apple silicon:** unzip mario-kart-7-macos-arm64.zip and open Mario Kart 7 Recompiled.app.
- **macOS Intel:** unzip mario-kart-7-macos-x86_64.zip and open Mario Kart 7 Recompiled.app.
- **Linux:** use mario-kart-7-linux-x86_64.AppImage, or extract mario-kart-7-linux-x86_64.tar.gz and run ./mario-kart-7.

The macOS app is not notarized. On first launch, macOS may block it; allow it through **System Settings → Privacy & Security → Open Anyway**. The Linux AppImage needs the host system's ALSA sound library.

## Building from source

The project uses the Rust workspace and requires Rust 1.95 or newer.

~~~
cargo build --release --locked -p zakuro
cargo test --release --workspace
~~~

The desktop binary is written to target/release/mario-kart-7 (or .exe on Windows). The macOS package script bundles MoltenVK into the app:

~~~
packaging/macos-app.sh target/release/mario-kart-7 1.0.4 mario-kart-7-macos-arm64.zip
~~~

For a normal user, the prebuilt packages on the Releases page are the easiest option.

## GitHub Actions and releases

- **CI** runs on pushes and pull requests. It builds and tests the Rust workspace on Windows, macOS, and Linux. It also keeps a Windows executable as a temporary Actions artifact.
- **Release** builds Windows x64, macOS Apple silicon, macOS Intel, and Linux x64 packages. It runs when a version tag is created or pushed. Once every platform build succeeds, it attaches the packages to the GitHub Release and publishes it. If you created a draft release on GitHub first, the workflow fills that draft with the packages and publishes it after the builds finish.
- To test a branch without publishing, open **Actions → Mario Kart 7 Recompiled Release → Run workflow**, enter the branch name (such as `main`) in `tag`, and set `publish` to `false`. The packages remain temporary Actions artifacts.

### Creating version 1.0.4 on GitHub

1. Open the repository and select **Releases → Draft a new release**.
2. In **Choose a tag**, type `v1.0.4`, then select **Create new tag: v1.0.4**.
3. Set **Target** to `main` so the release tag points to the merged 1.0.2 implementation.
4. Select **Save draft**. Creating the tag on the Releases page triggers the release build. The workflow will attach all four platform packages and publish the draft when they are ready.

The Rust workspace version is `1.0.4`. The matching release tag is `v1.0.4`; leave all previous version tags unchanged.

## Attribution and legal notes

This project is an unofficial, game-specific fork of [fearkov/zakuro](https://github.com/fearkov/zakuro) and uses [fearkov/3dsrecomp](https://github.com/fearkov/3dsrecomp). The original Zakuro project and the existing MIT-licensed portions retain their original notices in [LICENSE-MIT](LICENSE-MIT). The project is now distributed under GPL-3.0-or-later to permit integration of GPL-compatible 3DS runtime components; see [LICENSE](LICENSE).

Mario Kart 7 is a trademark of Nintendo. This project is unofficial and is not affiliated with or endorsed by Nintendo. No game ROM, generated title-specific C code, compiled game library, copyrighted game assets, or other game data is distributed. Users must provide their own lawful game dump and keep the resulting local recompilation on their own device.
