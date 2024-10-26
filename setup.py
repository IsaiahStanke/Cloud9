import setuptools

setuptools.setup(
    name='Cloud9',
    version='0.1.0',
    packages=setuptools.find_packages(),
    url='https://github.com/IsaiahStanke/Cloud9',
    license='GNU General Public License v3.0',
    author='Isaiah Stanke',
    author_email='',
    description='Signature-based Intrusion Detection System',
    install_requires=[
        'Flask',
        'Flask-SQLAlchemy',
        'Flask-Talisman',
        'Flask-Limiter',
        'Flask-Login',
        'redis',
        'marshmallow',
        'Werkzeug',
        'requests',
        'scapy',
        'psycopg2'
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)
