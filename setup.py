from setuptools import setup, find_packages

setup(
    name="flycatch_auth",
    version="0.1.0",
    description="A Python authentication package supporting Flask and FastAPI",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="Your Name",
    author_email="your.email@example.com",
    url="https://github.com/yourusername/flycatch_auth",
    packages=find_packages(),
    install_requires=[
        "flask",
        "fastapi",
        "pyjwt",
        "pydantic"
    ],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    python_requires=">=3.8",
)
