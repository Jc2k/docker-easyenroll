from setuptools import find_packages, setup

version = '0.0.0.dev0'

setup(
    name='docker_easyenroll',
    version=version,
    packages=find_packages(exclude=['ez_setup']),
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        'requests>=2.13.0',
        'cryptography',
    ],
    entry_points='''
        [console_scripts]
        docker-easyenroll = docker_easyenroll.scripts.docker_enrollment:main
    ''',
)
