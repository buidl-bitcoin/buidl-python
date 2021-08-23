from setuptools import setup, find_packages


with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="buidl",
    version="0.2.25",
    author="Example Author",
    author_email="author@example.com",
    description="An easy-to-use and fully featured bitcoin library written in pure python (no dependencies).",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/buidl-bitcoin/buidl-python",
    packages=find_packages(),
    include_package_data=True,  # https://stackoverflow.com/a/56689053
    scripts=["multiwallet.py", "singlesweep.py"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)
