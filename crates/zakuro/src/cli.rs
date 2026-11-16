//! command line parsing.

use zakuro_gpu::RendererKind;

#[derive(Debug, Clone)]
pub struct Options {
    /// the game to start, none to open the library.
    pub rom: Option<String>,
    /// the settings' choice when not given.
    pub renderer: Option<RendererKind>,
    /// window scale relative to the console's 400x480 combined screens, the
    /// settings' when not given.
    pub scale: Option<u32>,
    /// run without a window for this many frames, then report.
    pub headless: Option<u64>,
    pub profile: bool,
    pub new3ds: bool,
    /// skip loading a ROM entirely and just paint both screens solid colors.
    pub test_pattern: bool,
    /// a library of recompiled code for the title, or a directory of them.
    pub recompiled: Option<String>,
    /// draw on the host GPU rather than in software, the settings' choice
    /// when not given.
    pub hardware_rasterizer: Option<bool>,
    /// where saves live, instead of the usual place.
    pub data: Option<String>,
    /// interpret everything, whatever recompiled code there is.
    pub interpreter: bool,
    /// play no sound.
    pub mute: bool,
    /// recompile the game without a window, then exit.
    pub prepare: bool,
    /// start in borderless fullscreen.
    pub fullscreen: bool,
}

const USAGE: &str = "\
mario-kart-7 - Mario Kart 7 for desktop

usage: mario-kart-7 [rom.3ds|.cci|.cxi|.cia] [options]
       mario-kart-7 --game <rom.3ds|.cci|.cxi|.cia> [options]

This build only opens the Japan, Europe, USA, Korea, Taiwan and China releases of Mario Kart 7.
Without a game it opens a library folder and lists matching game dumps only.
The game dump must be decrypted. Recompile it locally from the library.

options:
  --game <path>                    game dump to open (also accepts the positional path)
  --fullscreen                     start in borderless fullscreen
  --renderer <vulkan|gl|software>  presentation backend
  --rasterizer <hardware|software> where the 3D is drawn
  --scale <n>                      window scale factor (default: 2)
  (Esc opens the menu over a game, F1 pauses, F11 goes fullscreen)
  --headless <frames>              run without a window and print a report
  --new3ds                         emulate a New 3DS
  --profile                        collect a sampling profile and print it
  --recompiled <path>              run locally recompiled code for this title
  --interpreter                    interpret everything
  --mute                           play no sound
  --prepare                        recompile the game given, without a window, printing
                                   progress lines, then exit (0 when it is ready)
  --data <dir>                     where settings and saves live (default:
                                   ~/.local/share/mario-kart-7,
                                   ~/Library/Application Support/mario-kart-7
                                   or %APPDATA%\\mario-kart-7)
  -h, --help                       show this message
";

pub fn parse() -> Result<Options, String> {
    let mut rom = None;
    let mut options = Options {
        rom: None,
        renderer: None,
        scale: None,
        headless: None,
        profile: false,
        new3ds: false,
        test_pattern: false,
        recompiled: None,
        hardware_rasterizer: None,
        data: None,
        interpreter: false,
        mute: false,
        prepare: false,
        fullscreen: false,
    };

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            "--renderer" => {
                let value = args.next().ok_or("--renderer needs a value")?;
                options.renderer = Some(
                    RendererKind::parse(&value).ok_or_else(|| format!("unknown renderer '{value}'"))?,
                );
            }
            "--scale" => {
                let value = args.next().ok_or("--scale needs a value")?;
                options.scale = Some(value.parse().map_err(|_| format!("'{value}' is not a scale"))?);
            }
            "--headless" => {
                let value = args.next().ok_or("--headless needs a frame count")?;
                options.headless = Some(
                    value
                        .parse()
                        .map_err(|_| format!("'{value}' is not a frame count"))?,
                );
            }
            "--game" => {
                let value = args.next().ok_or("--game needs a path")?;
                if rom.replace(value).is_some() {
                    return Err("only one game path may be given".to_owned());
                }
            }
            value if value.starts_with("--game=") => {
                let path = &value["--game=".len()..];
                if path.is_empty() {
                    return Err("--game needs a path".to_owned());
                }
                if rom.replace(path.to_owned()).is_some() {
                    return Err("only one game path may be given".to_owned());
                }
            }
            "--fullscreen" => options.fullscreen = true,
            "--new3ds" => options.new3ds = true,
            "--rasterizer" => {
                let value = args.next().ok_or("--rasterizer needs a value")?;
                options.hardware_rasterizer = Some(match value.as_str() {
                    "hardware" | "vulkan" | "gpu" => true,
                    "software" | "cpu" => false,
                    other => return Err(format!("unknown rasterizer '{other}'")),
                });
            }
            "--recompiled" => {
                options.recompiled = Some(args.next().ok_or("--recompiled needs a path")?);
            }
            "--data" => {
                options.data = Some(args.next().ok_or("--data needs a directory")?);
            }
            "--interpreter" => options.interpreter = true,
            "--mute" => options.mute = true,
            "--prepare" => options.prepare = true,
            "--profile" => options.profile = true,
            "--test-pattern" => options.test_pattern = true,
            // macOS hands an app it hasn't run before a process number
            other if cfg!(target_os = "macos") && other.starts_with("-psn_") => {}
            other if other.starts_with('-') => {
                return Err(format!("unknown option '{other}'"));
            }
            path => {
                if rom.replace(path.to_owned()).is_some() {
                    return Err("only one game path may be given".to_owned());
                }
            }
        }
    }

    options.rom = rom;
    if options.headless.is_some() && options.rom.is_none() && !options.test_pattern {
        print!("{USAGE}");
        return Err("--headless needs a game".to_owned());
    }
    if options.prepare && options.rom.is_none() {
        return Err("--prepare needs a game".to_owned());
    }
    Ok(options)
}
