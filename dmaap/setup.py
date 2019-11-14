from setuptools import setup, find_packages

setup(
    name = "dmaap",
    version = "1.3.5",
    packages=find_packages(),
    author = "AT&T",
    description = ("Cloudify plugin for creating DMaaP feeds and topics, and setting up publishers and subscribers."),
    license = "",
    keywords = "",
    url = "",
    zip_safe=False,
    #install_requires=[
    #    'python-consul>=0.7.0',
    #    'requests',
    #    'cloudify==3.4; python_version<"3"',
    #    'cloudify-common>=5.0.5; python_version>="3"',
    #],
)
