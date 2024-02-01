from setuptools import setup, find_packages

setup(
    name='scapy-iscsi',
    version='0.1.0',
    description='iSCSI layer for Scapy',
    author='Daria Bukharina, Konstantin Shelekhin',
    author_email='d.bukharina@yadro.com, k.shelekhin@yadro.com',
    py_modules=['scapy_iscsi'],
    package_dir={'scapy_iscsi': 'scapy_iscsi'},
    package_data={},
    packages=find_packages(),
    python_requires='>=3.6',
    install_requires=[
        'scapy ~=2.5.0',
    ],
)
