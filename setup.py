from setuptools import setup
import os

# Read version from heimdall/VERSION
with open('heimdall/VERSION') as f:
    VERSION = f.read().strip()

setup(
    name='heimdall-linux',
    version=VERSION,
    description='Interactive curses-based port and process viewer (using witr)',
    long_description=open('README.md', encoding='utf-8').read(),
    long_description_content_type='text/markdown',
    author='Serkan Sunel',
    author_email='serkan.sunel@gmail.com',
    url='https://github.com/sunels/heimdall',
    license='MIT',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Topic :: System :: Networking :: Monitoring',
        'Topic :: Security',
    ],
    packages=['heimdall'],
    package_data={'heimdall': ['VERSION']},
    install_requires=[
        'psutil',
        'requests',
        'pyyaml',
    ],
    entry_points={
        'console_scripts': [
            'heimdall=heimdall:cli_entry',
        ],
    },
)