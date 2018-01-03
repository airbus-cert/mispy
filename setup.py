from setuptools import setup

setup(
    name='mispy',
    version='0.2',
    description='A pythonic MISP module',
    url='https://github.com/nbareil/mispy',
    download_url = 'https://github.com/nbareil/mispy/archive/0.2.tar.gz',
    author='Nicolas Bareil',
    author_email='nico@chdir.org',
    keywords='misp',
    install_requires=['requests', 'lxml'],
    license='Apachev2',
    packages=['mispy'],
    zip_safe=False
)
