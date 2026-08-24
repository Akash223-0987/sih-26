from pathlib import Path

from setuptools import setup

ROOT = Path(__file__).resolve().parent
README = (ROOT / "README.md").read_text(encoding="utf-8")
REQUIREMENTS = [
    line.strip()
    for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
    if line.strip() and not line.startswith("#")
]

setup(
    name="ulpf",
    version="0.1.0",
    description="Universal Log Pre-processing Framework",
    long_description=README,
    long_description_content_type="text/markdown",
    author="National Technical Research Organisation",
    url="https://github.com/Aryan-202/sih-26",
    packages=[],
    scripts=["cmd/ulpf"],
    install_requires=REQUIREMENTS,
    python_requires=">=3.10",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Logging",
    ],
)
