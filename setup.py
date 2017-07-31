from setuptools import setup

setup(
    name='mispy',
    version='0.1',
    description='A pythonic MISP module',
    url='https://github.com/nbareil/python-misp',
    author='Nicolas Bareil',
    author_email='nico@chdir.org',
    keywords='misp',
    install_requires=['requests', 'lxml'],
    license='Apachev2',
    packages=['mispy'],
    zip_safe=False
)
