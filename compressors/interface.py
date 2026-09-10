"""API for various compressors."""

import os
from pathlib import Path
import subprocess

DIR_PATH = Path(os.path.dirname(os.path.abspath(__file__)))

BUILD_DIR = "build"

PATH_TO_FLATE2 = DIR_PATH / Path("flate2-zpipe/target/release")
PATH_TO_ZLIB = DIR_PATH / "zlib" / BUILD_DIR / "test"
PATH_TO_ZLIB_CF = DIR_PATH / "cloudflare-zlib" / BUILD_DIR
PATH_TO_ZLIB_CR = DIR_PATH / "chromium-zlib" / BUILD_DIR
PATH_TO_ZLIB_GO = DIR_PATH / "zlib-go"
PATH_TO_ZLIB_NG = DIR_PATH / "zlib-ng" / BUILD_DIR

__all__ = [
    "GZipCompressor",
    "MiniGZipCompressor",
    "ZlibMiniCompressor",
    "ZlibCloudflareCompressor",
    "ZlibChromiumCompressor",
    "GoFlateCompressor",
    "ZlibNGCompressor",
    "RustFlate2Compressor",
]


class GZipCompressor:
    """A GZip compressor, implemented as an interface to the `gzip` program."""

    def __init__(self, level: int):
        assert 1 <= level <= 9
        self.level = level

    def compress(self, data: bytes | bytearray | memoryview) -> bytes:
        return subprocess.run(
            [
                "gzip",
                "--stdout",
                "--no-name",
                "-{}".format(self.level),
            ],
            input=data,
            capture_output=True,
            check=True,
        ).stdout


class MiniGZipCompressor:
    """A minimal gzip compressor for testing, shipped along with many DEFLATE
    implementations forked from zlib."""

    def __init__(self, level: int, dir_path: str | Path, bin_name="minigzip"):
        assert 1 <= level <= 9
        self.level = level
        self.dir_path = Path(dir_path)
        self.bin_name = bin_name

    def compress(self, data: bytes | bytearray | memoryview) -> bytes:
        return subprocess.run(
            [self.dir_path / self.bin_name, "-c", "-{}".format(self.level)],
            input=data,
            capture_output=True,
            check=True,
        ).stdout


class ZlibMiniCompressor(MiniGZipCompressor):
    """An interface to the `minigzip` program in zlib."""

    def __init__(self, level: int, dir_path: str | Path = PATH_TO_ZLIB):
        super().__init__(level=level, dir_path=dir_path)


class ZlibCloudflareCompressor(MiniGZipCompressor):
    """An interface to the `minigzip` program in the Cloudflare fork of zlib."""

    def __init__(self, level: int, dir_path: str | Path = PATH_TO_ZLIB_CF):
        super().__init__(level=level, dir_path=dir_path)


class ZlibChromiumCompressor(MiniGZipCompressor):
    """An interface to the `minigzip` program in the Chromium fork of zlib."""

    def __init__(self, level: int, dir_path: str | Path = PATH_TO_ZLIB_CR):
        super().__init__(level=level, dir_path=dir_path, bin_name="minigzip_bin")


class GoFlateCompressor:
    """An interface to the Go/flate compressor snippet I wrote."""

    def __init__(self, level: int, dir_path: str | Path = PATH_TO_ZLIB_GO):
        assert 0 <= level <= 9
        self.level = level
        self.dir_path = Path(dir_path)

    def compress(self, data: bytes | bytearray | memoryview) -> bytes:
        return subprocess.run(
            [
                str(self.dir_path / "go-zpipe"),
                "-level={}".format(self.level),
            ],
            input=data,
            capture_output=True,
            check=True,
        ).stdout


class ZlibNGCompressor:
    """An interface to the `minideflate`/`minigzip` program in zlib-ng."""

    MINI_DEFLATE = "minideflate"
    MINI_GZIP = "minigzip"

    def __init__(
        self,
        level: int,
        dir_path: str | Path = PATH_TO_ZLIB_NG,
        mode: str = MINI_GZIP,
    ):
        assert 0 <= level <= 9
        self.level = level
        self.dir_path = Path(dir_path)
        self.mode = mode

    def compress(self, data: bytes | bytearray | memoryview) -> bytes:
        return subprocess.run(
            [self.dir_path / self.mode, "-c", "-{}".format(self.level)],
            input=data,
            capture_output=True,
            check=True,
        ).stdout


class RustFlate2Compressor:
    """An interface to the `flate2` compression library with the default
    `miniz_oxide` backend in Rust, using a snippet I wrote."""

    def __init__(self, level: int, dir_path: str | Path = PATH_TO_FLATE2):
        assert 0 <= level <= 10
        self.level = level
        self.dir_path = Path(dir_path)

    def compress(self, data: bytes | bytearray | memoryview) -> bytes:
        return subprocess.run(
            [self.dir_path / "flate2-zpipe", "-l", f"{self.level}"],
            input=data,
            capture_output=True,
            check=True,
        ).stdout
