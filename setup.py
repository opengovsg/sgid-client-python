from setuptools import find_packages, setup

setup(
    name='sgidclient',
    packages=find_packages(),
    version='0.1.0',
    description='sgID Client SDK for Python',
    author='Open Goveernment Products',
    license='MIT',
    install_requires=['JWCrypto', 'Authlib', 'requests'],
    setup_requires=['pytest-runner'],
    tests_require=['pytest==7.3.1', 'responses'],
    test_suite='tests',
)
