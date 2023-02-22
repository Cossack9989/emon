from setuptools import setup, find_packages

setup(
    name="emon",
    packages=find_packages("src"),
    package_dir={"": "src"},
    version='0.0.0',
    install_requires=[
        'bcc'
    ],
    author="C0ss4ck",
    author_email="c0ss4ck9989@gmail.com",
    description="ebpf tools for machine monitor"
)