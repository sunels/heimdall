from setuptools import setup

setup(
    name='heimdall',
    version='0.1.0',
    description='Interactive curses-based port and process viewer (using witr)',
    long_description=open('README.md', encoding='utf-8').read(),
    long_description_content_type='text/markdown',
    author='Serkan',
    author_email='serkan.sunel@gmail.com',
    url='https://github.com/sunels/heimdall',
    license='MIT',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console :: Curses',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3 :: Only',
        'Topic :: System :: Monitoring',
        'Topic :: System :: Systems Administration',
    ],
    python_requires='>=3.8',
    py_modules=['heimdall'],
    entry_points={
        'console_scripts': [
            'heimdall = heimdall:cli_entry',   # ← BURAYI DEĞİŞTİR
        ],
    },
    install_requires=[],
    # extras_require={
    #     'dev': ['black', 'flake8'],
    # },
    include_package_data=True,
)