from pathlib import Path
from setuptools import find_packages, setup

ROOT = Path(__file__).resolve().parent
README = (ROOT / "README.md").read_text(encoding="utf-8") if (ROOT / "README.md").exists() else ""
REQUIREMENTS = [
    line.strip()
    for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
    if line.strip() and not line.startswith("#")
]

setup(
    name="pytrace",
    version="0.1.0",
    description="Universal Developer Observability & Structured Telemetry Framework for Python",
    long_description=README,
    long_description_content_type="text/markdown",
    author="Aryan-202 / PyTrace Contributors",
    url="https://github.com/Aryan-202/sih-26",
    packages=find_packages(include=["pytrace", "pytrace.*"]),
    install_requires=REQUIREMENTS,
    python_requires=">=3.9",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.14",
        "Topic :: System :: Logging",
        "Topic :: System :: Monitoring",
        "Topic :: Software Development :: Libraries :: Application Frameworks",
    ],
)
