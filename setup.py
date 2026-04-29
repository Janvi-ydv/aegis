from setuptools import setup, find_packages

setup(
    name="aegis",
    version="1.0.0",
    description="AEGIS — Adaptive Exploitation & Global Intelligence System",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="Shubham",
    python_requires=">=3.10",
    packages=find_packages(exclude=["tests*", "docs*"]),
    install_requires=[
        "rich==13.7.1",
        "requests==2.31.0",
        "python-nmap==0.7.1",
        "fpdf2==2.7.9",
        "python-dotenv==1.0.1",
    ],
    entry_points={
        "console_scripts": [
            "aegis=aegis:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Topic :: Security",
    ],
)
