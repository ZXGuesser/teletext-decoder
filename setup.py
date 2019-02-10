from setuptools import setup

setup(
    name='teletext-decoder',
    version='0.1',
    author='Alistair Cree',
    author_email='alistair@zxnet.co.uk',
    url='http://github.com/ZXGuesser/teletext-decoder',
    packages=['teletextdecoder'],
    entry_points={
        'console_scripts': [
            'teletext-decoder = teletextdecoder.decoder:main',
        ]
    },
    install_requires=['crcmod', 'click'],
    python_requires='>=3',
)
