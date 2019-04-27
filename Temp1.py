import os
import shutil


def showIconPath():
    currentWorkingDir = os.getcwd()
    print("Current Working Dir : ", currentWorkingDir)
    iconPath = currentWorkingDir + "/" + "icon" + "/" + "app.ico"
    print("Icon Path : ", iconPath)
    fullIconPath = os.path.join(currentWorkingDir, "icon", "app.ico")
    print("Ful Icon Path : ", fullIconPath)


def deleteDirs():
    CLEAN_FILES = 'build dist __pycache__ *.egg-info'.split(' ')
    for fileName in CLEAN_FILES:
        currentWorkingDir = os.getcwd()
        fileOrDirName = os.path.join(currentWorkingDir, fileName)
        if os.path.isdir(fileOrDirName):
            shutil.rmtree(fileName, ignore_errors=True)
        elif os.path.isfile(fileOrDirName):
            os.remove(fileOrDirName)



if __name__ == "__main__":
    pass
    # showIconPath()
    deleteDirs()
