from setuptools import setup, find_packages

setup(
    name='mv-cli',
    packages=find_packages(),
    include_package_data=True,
    entry_points={
        'console_scripts': ['mv-cli=click_cli:cli']
    },
    install_requires=[
        'eth-utils == 1.6.1',
        'requests == 2.22.0',
        'eth-account == 0.5.9',
        'solidity_parser == 0.0.7',
        'click == 7.0',
        "tenacity==6.2.0",
        "antlr4-python3-runtime>=4.7,<4.8",
        "colorama==0.4.3"
    ],
    classifiers=[
            "Programming Language :: Python :: 3",
            "License :: OSI Approved :: MIT License",
            "Operating System :: OS Independent",
        ],
    version="0.1"
)