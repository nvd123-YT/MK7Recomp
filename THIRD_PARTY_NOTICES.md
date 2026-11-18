# Third-party notices

## Zakuro and 3dsrecomp

The project is derived from [fearkov/zakuro](https://github.com/fearkov/zakuro) and uses [fearkov/3dsrecomp](https://github.com/fearkov/3dsrecomp). Their original MIT license notice is preserved in [LICENSE-MIT](LICENSE-MIT).

## Azahar / Citra 3GX loader and CSND

The 3GX loader behavior, plugin service contracts, and CSND hardware behavior were adapted with reference to [Azahar](https://github.com/azahar-emu/azahar), including:

- `src/core/file_sys/plugin_3gx.cpp`
- `src/core/file_sys/plugin_3gx.h`
- `src/core/file_sys/plugin_3gx_bootloader.h`
- `src/core/hle/service/plgldr/plgldr.cpp`
- `src/core/hle/service/plgldr/plgldr.h`
- `src/audio_core/csnd.cpp`
- `src/audio_core/csnd.h`
- `src/core/hle/service/csnd/csnd_snd.cpp`

Azahar's 3GX loader and CSND service sources are licensed under GPL-3.0-or-later. The original Citra bootloader payload header is marked GPL-2.0-or-later and includes a separate MIT notice from The Pixellizer Group. GPL-2.0-or-later permits use under GPL-3.0-or-later.

Copyright notices from the upstream sources remain applicable. The bootloader payload is reproduced from the Azahar/Citra implementation; the Rust loader, service state, and memory integration are an adaptation for this emulator.

## Azahar / Citra PICA rendering

The PICA200 shadow-texture behavior in `crates/zakuro-gpu/shaders/raster.frag`
was adapted with reference to Azahar's PICA shader and register implementation,
including:

- `src/video_core/shader/generator/glsl_fs_shader_gen.cpp` (Shadow2D and ShadowCube coordinate transforms, depth comparison, and filtering)
- `src/video_core/pica/regs_texturing.h` (PICA texture-type and shadow-register bitfields)
- `src/video_core/renderer_opengl/gl_rasterizer.cpp`
- `src/video_core/renderer_vulkan/vk_rasterizer.cpp` (special texture binding)

The referenced Azahar shader and renderer sources are licensed under
GPL-3.0-or-later; the PICA register header is GPL-2.0-or-later. These terms are
compatible with this project's GPL-3.0-or-later licensing. The corresponding
upstream copyright and license notices remain applicable to any copied or
adapted source.

## ScarletNX CSND reference

The CSND service behavior was also cross-checked against [ScarletNX](https://github.com/scarletnx/ScarletNX), whose CSND implementation is GPL-3.0-or-later and identifies Azahar as its upstream reference.

## The Pixellizer Group bootloader notice

Copyright 2022 The Pixellizer Group.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
