project(
    'qbinary',
    version: run_command('grep', '-oP', '__version__ = "\K[0-9.]+', 'src/qbinary/__version__.py').stdout().strip(),
    license: 'Apache-2.0',
    license_files: 'LICENSE',
    meson_version: '>= 1.1.0',
)

py = import('python').find_installation(pure: false)
py_deps = py.dependency()

subdir('src/qbinary')
