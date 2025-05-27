project(
    'qbinary',
    version: run_command(
        find_program('python3'), 'src/qbinary/__version__.py', check: true
    ).stdout().strip(),
    license: 'Apache-2.0',
    license_files: 'LICENSE',
    meson_version: '>= 1.1.0',
)

py = import('python').find_installation(pure: false)

subdir('src/qbinary')
