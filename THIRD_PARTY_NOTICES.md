# Licensing scope and third-party components

QBox's original source code and documentation are licensed under the MIT
license in [LICENSE](LICENSE). The eBPF program in `guest/audit.bpf.c` is
additionally available under GPL-2.0-only, at your choice
(`SPDX-License-Identifier: MIT OR GPL-2.0-only`). Its kernel-facing license
declaration is `Dual MIT/GPL`. The GPL text is in
[LICENSES/GPL-2.0-only.txt](LICENSES/GPL-2.0-only.txt).

QBox's MIT license does not relicense third-party software. QEMU is installed
separately, and the image assembler downloads Linux, Alpine packages, agent
CLIs, and build dependencies into Git-ignored `build/` and `assets/`
directories. These components retain their upstream licenses and terms.

Relevant upstream sources include:

- [QEMU licensing](https://www.qemu.org/docs/master/about/license.html).
- [Linux kernel licensing](https://docs.kernel.org/process/license-rules.html).
- [Alpine package metadata and licenses](https://pkgs.alpinelinux.org/packages).
- [Codex source and license](https://github.com/openai/codex).
- [Claude Code legal and compliance documentation](https://code.claude.com/docs/en/legal-and-compliance).
- [OpenCode source and license](https://github.com/anomalyco/opencode).
- [libbpf source and licenses](https://github.com/libbpf/libbpf).
- [elfutils licensing](https://sourceware.org/elfutils/).

Before distributing prepared images or statically linked guest runners,
review the licenses of the exact included versions, preserve required
copyright and license notices, and provide corresponding source or relinking
materials where required. Check the agent vendors' redistribution terms as
well. Build-time dependencies and their runtime libraries may have different
requirements.

Generated `agents-manifest.json` files record input URLs, versions, and hashes
for identifying build inputs. They are provenance records, not a complete
license inventory or evidence of redistribution compliance. This document is
also not a complete inventory of an assembled image's dependencies.
