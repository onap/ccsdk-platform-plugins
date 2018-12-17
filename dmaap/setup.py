from setuptools import setup, find_packages

setup(
    name = "cloudifydmaapplugin",
    version = "1.2.0+t.0.11",
    packages=find_packages(),
    author = "AT&T",
    description = ("Cloudify plugin for creating DMaaP feeds and topics, and setting up publishers and subscribers."),
    license = "",
    keywords = "",
    url = "",
    zip_safe=False,
    install_requires = [
        "python-consul==0.7.0"
    ]
)
