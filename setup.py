import shutil

from setuptools import setup, find_packages, Command, glob
from setuptools.command.install import install
import subprocess
import os


class CustomCleanCommand(Command):
    CLEAN_FILES = 'build dist __pycache__ migrator.egg-info main.spec'.split(' ')
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        for fileName in self.CLEAN_FILES:
            print("Name : ", fileName)
            currentWorkingDir = os.getcwd()
            fileOrDirName = os.path.join(currentWorkingDir, fileName)
            if os.path.isdir(fileOrDirName):
                shutil.rmtree(fileName, ignore_errors=True)
            elif os.path.isfile(fileOrDirName):
                os.remove(fileOrDirName)
            # if os.path.isdir(fileName):
            #     shutil.rmtree(fileName, ignore_errors=True)
            # else:
            #     os.remove(fileName)


# class CustomCleanCommand(Command):
#     """Custom clean command to tidy up the project root."""
#     CLEAN_FILES = './build ./dist ./*.pyc ./*.tgz ./*.egg-info'.split(' ')
#     user_options = []
#
#     def initialize_options(self):
#         pass
#
#     def finalize_options(self):
#         pass
#
#     def run(self):
#         global here
#
#         for path_spec in self.CLEAN_FILES:
#             # Make paths absolute and relative to this path
#             abs_paths = glob.glob(os.path.normpath(os.path.join(here, path_spec)))
#             for path in [str(p) for p in abs_paths]:
#                 if not path.startswith(here):
#                     # Die if path in CLEAN_FILES is absolute + outside this directory
#                     raise ValueError("%s is not a path inside %s" % (path, here))
#                 print('removing %s' % os.path.relpath(path))
#                 shutil.rmtree(path)


# os.system('del ./build ./dist ./*.pyc ./*.tgz ./*.egg-info')

# try:
#     from setupext import janitor
#
#     CleanCommand = janitor.CleanCommand
# except ImportError:
#     CleanCommand = None
#
# cmd_classes = {}
# if CleanCommand is not None:
#     cmd_classes['clean'] = CleanCommand


class ExeCreateCommand(install):
    """Custom install setup to help run shell commands (outside shell) before installation"""

    def run(self):
        print("I am going to execute ?")
        currentWorkingDir = os.getcwd()
        fullIconPath = os.path.join(currentWorkingDir, "icon", "app.ico")
        pyInstallerCmd = "pyinstaller --onefile --console --icon=" + fullIconPath + " " + "main.py"
        #         subprocess.run(["pyinstaller --onefile --console main.py"])
        # os.system("pyinstaller --onefile --console --icon=./icon/app.ico main.py")
        print("Command to execute : ", pyInstallerCmd)
        os.system(pyInstallerCmd)
        install.run(self)


setup(
    cmdclass={'clean': CustomCleanCommand, 'install': ExeCreateCommand},
    # cmdclass={'install': ExeCreateCommand},
    # setup_requires=['setupext.janitor'],
    # cmdclass=cmd_classes,
    name='migrator',
    version='0.0.1',
    description='A simple tool for migration',
    url='http://github.com/debjava/py-exe-creator1',
    author='Debadatta Mishra',
    author_email='deba.java@gmail.com',
    license='MIT',
    packages=find_packages(exclude=["tests", "*.tests", "*.tests.*", "tests.*"]),
    install_requires=[
        'panda', 'numpy', 'auto-py-to-exe', 'setupext-janitor'
    ],
    zip_safe=False)
