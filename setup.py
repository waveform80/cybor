from setuptools import setup
from Cython.Build import cythonize

classifiers = ['Development Status :: 5 - Production/Stable',
               'Operating System :: POSIX :: Linux',
               'License :: OSI Approved :: MIT License',
               'Intended Audience :: Developers',
               'Programming Language :: Python :: 3',
               'Programming Language :: Python :: Implementation :: CPython',
               'Topic :: Software Development']

setup(
    name='cybor',
    version='0.1',
    author='Dave Jones',
    author_email='dave@waveform.org.uk',
    description='A high performance, flexible CBOR implementation',
    long_description='',
    license='MIT',
    keywords='CBOR',
    url='https://github.com/waveform80/cybor.git',
    classifiers=classifiers,
    extras_require={'test': ['pytest']},
    ext_modules=cythonize("cybor/*.pyx", annotate=True,
                          compiler_directives={'language_level': 3})
)
