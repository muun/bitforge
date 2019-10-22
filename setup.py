import setuptools
import sys

setuptools.setup(
  name = 'bitforge',
  version = '0.3',
  url = 'https://github.com/coinforge/bitforge',

  author = 'Yemel Jardi',
  author_email = 'angel.jardi@gmail.com',

  description = 'A python bitcoin library',
  keywords = ['bitcoin', 'altcoin'], # arbitrary keywords

  packages = setuptools.find_packages(),

  setup_requires=['pytest-runner'],
  tests_require=['pytest'],
  install_requires = ['ecdsa==0.13.3'] + (['enum34==1.0.4'] if sys.version_info < (3, 4) else []),

  classifiers = [
      'Development Status :: 4 - Beta',
      'Intended Audience :: Developers',
      'License :: OSI Approved :: MIT License',
      'Operating System :: OS Independent',
      'Programming Language :: Python',
      'Programming Language :: Python :: 2',
      'Programming Language :: Python :: 2.7',
      'Programming Language :: Python :: 3',
      'Programming Language :: Python :: 3.3',
      'Programming Language :: Python :: 3.4',
      'Programming Language :: Python :: 3.5',
      'Topic :: Internet',
      'Topic :: Software Development :: Libraries :: Python Modules',
  ],
)
