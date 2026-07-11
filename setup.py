"""
MrNothing Shield — Mobile Security Audit Framework
Setup configuration
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="mrnothing-shield",
    version="1.0.0",
    author="David Carmel Alex",
    author_email="forbesdid@gmail.com",
    description="Mobile Security Audit Framework — Detects spyware, hidden apps, and malicious permissions",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Davidcarmelalex/mrnothing-shield",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: POSIX :: Linux",
        "Operating System :: Android",
    ],
    python_requires=">=3.11",
    install_requires=[
        "click>=8.1.0",
        "rich>=13.0.0",
        "jinja2>=3.1.0",
        "requests>=2.31.0",
        "cryptography>=41.0.0",
        "reportlab>=4.0.0",
        "pyyaml>=6.0.1",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.5.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "shield=shield.cli:main",
        ],
    },
)
