from setuptools import setup, find_packages
import os

version = '1.0'

setup(name='uvc.jwt',
      version=version,
      description="",
      long_description=open("README.txt").read() + "\n" +
                       open(os.path.join("docs", "HISTORY.txt")).read(),
      classifiers=[
        "Programming Language :: Python",
        ],
      keywords='',
      author='',
      author_email='',
      url='http://svn.plone.org/svn/collective/',
      license='GPL',
      packages=find_packages(exclude=['ez_setup']),
      namespace_packages=['uvc'],
      include_package_data=True,
      zip_safe=False,
      install_requires=[
          'setuptools',
          'uvcsite',
          'jwcrypto >= 0.4.1',
          'grokcore.json',
          'zope.annotation',
          'pytz',
          'uvc.services',
      ],
      entry_points={
         'z3c.autoinclude.plugin': 'target=uvcsite', 
      }
      )
