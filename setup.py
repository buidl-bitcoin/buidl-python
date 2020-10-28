from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="buidl",
    version="0.1.3",
    author="Example Author",
    author_email="author@example.com",
    description="An easy-to-use and fully featured bitcoin library written in pure python (no dependencies).",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/buidl-bitcoin/buidl-python",
    packages=find_packages(),
    entry_points={
        "console_scripts": ["multiwallet=multiwallet:main"],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)
