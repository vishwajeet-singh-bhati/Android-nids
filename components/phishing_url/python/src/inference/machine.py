"""Describe the machine a measurement ran on (for benchmark and parity reports).

On Linux on Arm (Raspberry Pi, a phone running Linux in Termux) the CPU cores
are listed by type: phones mix fast and slow cores, and that changes how
many PyTorch threads help. No host names, serial numbers or user names are
recorded.
"""
from __future__ import annotations

import os
import platform
import re
from collections import Counter
from pathlib import Path

# MIDR "CPU part" numbers of Arm Ltd. cores (implementer 0x41), as in the Linux
# kernel's arch/arm64/include/asm/cputype.h. Unknown parts are reported as raw numbers.
ARM_CORES = {
    "0xd03": "Cortex-A53", "0xd04": "Cortex-A35", "0xd05": "Cortex-A55", "0xd07": "Cortex-A57",
    "0xd08": "Cortex-A72", "0xd09": "Cortex-A73", "0xd0a": "Cortex-A75", "0xd0b": "Cortex-A76",
    "0xd0d": "Cortex-A77", "0xd41": "Cortex-A78", "0xd44": "Cortex-X1", "0xd46": "Cortex-A510",
    "0xd47": "Cortex-A710", "0xd48": "Cortex-X2", "0xd4d": "Cortex-A715", "0xd4e": "Cortex-X3",
    "0xd80": "Cortex-A520", "0xd81": "Cortex-A720", "0xd82": "Cortex-X4",
}


def _read(path: str) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").strip("\x00\n ")
    except OSError:
        return None


def parse_cpuinfo(text: str, max_khz=lambda cpu: None) -> dict[str, int]:
    """Count cores by type in /proc/cpuinfo text, e.g. {"Cortex-A76 @ 2400 MHz": 4}."""
    cores = []
    for block in re.split(r"\n\s*\n", text):
        fields = dict((k.strip(), v.strip()) for k, v in
                      (line.split(":", 1) for line in block.splitlines() if ":" in line))
        if not fields.get("processor", "").isdigit():
            continue
        part, impl = fields.get("CPU part", "").lower(), fields.get("CPU implementer", "").lower()
        name = ARM_CORES.get(part) if impl == "0x41" else None
        name = name or fields.get("model name") or (f"implementer {impl} part {part}" if part else "unknown")
        khz = max_khz(fields["processor"])
        cores.append(f"{name} @ {int(khz) // 1000} MHz" if khz and str(khz).isdigit() else name)
    return dict(Counter(cores))


def linux_cpu() -> dict:
    """Core types and maximum clock per core, as far as /proc and /sys tell."""
    return {"cores": parse_cpuinfo(_read("/proc/cpuinfo") or "",
                                   lambda cpu: _read(f"/sys/devices/system/cpu/cpu{cpu}/cpufreq/cpuinfo_max_freq")),
            "board": _read("/proc/device-tree/model")}


def linux_env(release: str, root: Path = Path("/")) -> dict:
    """Is Android underneath, and is the kernel name made up by proot?

    Inside proot-distro, uname reports a made-up kernel ("6.17.0-PRoot-Distro"), so the
    kernel name cannot show Android. Android's /system/build.prop can: proot-distro makes
    /system visible by default, and is_file() needs no read permission.
    """
    return {"proot": "proot" in release.lower(),
            "android": "android" in release.lower() or (root / "system" / "build.prop").is_file()}


def machine_info() -> dict:
    import numpy
    import torch
    out = {"system": platform.system(), "release": platform.release(), "machine": platform.machine(),
           "processor": platform.processor(), "cpu_count": os.cpu_count(),
           "python": platform.python_version(), "torch": str(torch.__version__),
           "torch_threads": torch.get_num_threads(), "numpy": numpy.__version__}
    try:
        import sklearn
        out["sklearn"] = sklearn.__version__
    except ImportError:
        pass
    if platform.system() == "Linux":
        out.update(linux_cpu())
        out.update(linux_env(platform.release()))
    return out
