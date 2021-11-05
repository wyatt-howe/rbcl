"""
Setup, package, and build file for the rbcl cryptography library.
"""
import sys
import os
import os.path
import platform
import glob
import subprocess
import errno
import functools
from distutils.sysconfig import get_config_vars
from setuptools import Distribution, setup
from setuptools.command.build_ext import build_ext as _build_ext

try:
    from setuptools.command.build_clib import build_clib as _build_clib
except ImportError:
    from distutils.command.build_clib import build_clib as _build_clib

def here(*paths):
    return os.path.relpath(os.path.join(*paths))

def abshere(*paths):
    return os.path.abspath(here(*paths))

sodium = functools.partial(here, "rbcl/libsodium/")

def which(name, flags=os.X_OK): # Taken from twisted.
    result = []
    exts = filter(None, os.environ.get("PATHEXT", "").split(os.pathsep))
    path = os.environ.get("PATH", None)
    if path is None:
        return []
    for p in os.environ.get("PATH", "").split(os.pathsep):
        p = os.path.join(p, name)
        if os.access(p, flags):
            result.append(p)
        for e in exts:
            pext = p + e
            if os.access(pext, flags):
                result.append(pext)
    return result

def use_system():
    if os.environ.get("SODIUM_INSTALL") == "system":
        return True # Don't compile the bundled sodium copy.
    else:
        return False # Use the bundled copy.

class Distribution(Distribution):
    def has_c_libraries(self):
        return not use_system()

class build_clib(_build_clib):
    def get_source_files(self):
        files = glob.glob(here("rbcl/libsodium/*"))
        files += glob.glob(here("rbcl/libsodium/*/*"))
        files += glob.glob(here("rbcl/libsodium/*/*/*"))
        files += glob.glob(here("rbcl/libsodium/*/*/*/*"))
        files += glob.glob(here("rbcl/libsodium/*/*/*/*/*"))
        files += glob.glob(here("rbcl/libsodium/*/*/*/*/*/*"))
        files += glob.glob(here("rbcl/libsodium/*/*/*/*/*/*/*"))
        return files

    def build_libraries(self, libraries):
        raise Exception("build_libraries")

    def check_library_list(self, libraries):
        raise Exception("check_library_list")

    def get_library_names(self):
        return ["sodium"]

    def run(self):
        if use_system():
            return

        # Use Python's build environment variables.
        build_env = {
            key: val
            for key, val in get_config_vars().items()
            if key in ("LDFLAGS", "CFLAGS", "CC", "CCSHARED", "LDSHARED")
            and key not in os.environ
        }
        os.environ.update(build_env)

        # Ensure our temporary build directory exists.
        build_temp = os.path.abspath(self.build_temp)
        try:
            os.makedirs(build_temp)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise

        # Ensure all of our executable files have their permissions set.
        for filename in [
            "rbcl/libsodium/autogen.sh",
            "rbcl/libsodium/compile",
            "rbcl/libsodium/configure",
            "rbcl/libsodium/depcomp",
            "rbcl/libsodium/install-sh",
            "rbcl/libsodium/missing",
            "rbcl/libsodium/msvc-scripts/process.bat",
            "rbcl/libsodium/test/default/wintest.bat",
        ]:
            os.chmod(here(filename), 0o755)

        if not which("make"):
            raise Exception("ERROR: The 'make' utility is missing from PATH")

        # Locate our configure script.
        configure = abshere("rbcl/libsodium/configure")

        # Run `./configure`.
        configure_flags = [
            "--disable-shared",
            "--enable-static",
            "--disable-debug",
            "--disable-dependency-tracking",
            "--with-pic",
        ]
        if platform.system() == "SunOS":
            # On Solaris, libssp doesn't link statically and causes linker
            # errors during import.
            configure_flags.append("--disable-ssp")
        if os.environ.get("SODIUM_INSTALL_MINIMAL"):
            configure_flags.append("--enable-minimal")
        subprocess.check_call(
            [configure]
            + configure_flags
            + ["--prefix", os.path.abspath(self.build_clib)],
            cwd=build_temp,
        )

        make_args = os.environ.get("LIBSODIUM_MAKE_ARGS", "").split()
        # Build the library.
        subprocess.check_call(["make"] + make_args, cwd=build_temp)

        # Check the built library.
        subprocess.check_call(["make", "check"] + make_args, cwd=build_temp)

        # Install the built library.
        subprocess.check_call(["make", "install"] + make_args, cwd=build_temp)

class build_ext(_build_ext):
    def run(self):
        if self.distribution.has_c_libraries():
            build_clib = self.get_finalized_command("build_clib")
            self.include_dirs.append(os.path.join(build_clib.build_clib, "include"),)
            self.library_dirs.insert(0, os.path.join(build_clib.build_clib, "lib64"),)
            self.library_dirs.insert(0, os.path.join(build_clib.build_clib, "lib"),)

        return _build_ext.run(self)

with open("README.rst", "r") as fh:
    long_description = fh.read()

name = "rbcl"
version = "0.2.0"

setup(
    name=name,
    version=version,
    license="MIT",
    url="https://github.com/nthparty/rbcl",
    author="Nth Party, Ltd.",
    author_email="team@nthparty.com",
    description="Python library that provides wrappers around the Ristretto group operations in libsodium.",
    long_description=long_description,
    long_description_content_type="text/x-rst",
    test_suite="nose.collector",
    tests_require=["nose"],
    packages=["rbcl"],
    ext_package="rbcl",
    cffi_modules=["rbcl/sodium_ffi.py:sodium_ffi"],
    cmdclass={
        "build_clib": build_clib,
        "build_ext": build_ext,
    },
    distclass=Distribution,
    zip_safe=False
)
