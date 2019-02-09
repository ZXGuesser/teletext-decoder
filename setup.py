from setuptools import setup

setup(
    name='teletext-decoder',
    version='0.1',
    author='Author Name',
    author_email='author@example.com',
    url='http://github.com/ZXGuesser/teletext-decoder',
    packages=['teletextdecoder'],
    entry_points={
        'console_scripts': [
            'teletext-decoder = teletextdecoder.decoder:main',
        ]
    },
    install_requires=['crcmod'],
    python_requires='>=3',
)
