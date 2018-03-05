from setuptools import find_packages, setup

version = '1.0.3'

setup(
    name='docker_easyenroll',
    version=version,
    packages=find_packages(exclude=['ez_setup']),
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        'cryptography',
    ],
    extras_require={
        'client':  ["requests>=2.13.0"],
        'server': [],
    },
    entry_points='''
        [console_scripts]
        docker-easyenroll = docker_easyenroll.scripts.docker_enrollment:main
    ''',
)
