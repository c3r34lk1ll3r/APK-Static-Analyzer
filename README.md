# APK Static Analyzer

## Description
This tool allow to perform reverse engineering activity for APK files show various information.

## Installation
*Android Logging Tool* requirement:
- Python 2.7
- IPython

Step to use APK Static Analyzer:

1. Install all requirements
3. Run `python cli.py` (for command line interface) or `python gui.py` (for GUI [NOT YET IMPLEMENTED])

## Usage

In order to execute the tool run:

`python cli.py`

This command open a interactive shell using IPython.

The step to load an apk are:
```
1. python cli.py
2. a=APK('<apkfile.apk>')
3. dex=a.Dex()
4. d=DexFile(dex[0])
5. ...
```

### Command

The command line interface use various command:

- `a=APK('<apkfile.apk'>)` : Allow to load an APK files and save the instance in 'a'.
- `dex=a.Dex()` : Retreive the list of classes.dex file saved inside APK. The list is saved in 'dex'. This is because it is possible to find APK with more than one classes.dex file.
- `d=DexFile(dex[0])` : Create an instance of DexFile using dex[0] files and saved in 'd'.

After we create the instance of DexFile we can use that for obtain information about code:

- `d.printHeader()`         : Print the header of DEX file.

- `d.getClassesList(<var>)` : Get list of classes. The return value is a dictionary that use as key the class name and value an index.

- `d.getMethodList(<var>)`  : Get list of method. The return value is a dictionary that use as key the method name and value an index.

- `d.getStringList(<var>)`  : Get list of string. The return value is a dictionary that use as key the string name and value an index.

- `d.getTypeList(<var>)`    : Get list of type. The return value is a dictionary that use as key the type name and value an index.

- `d.getClass(<var>)`       : Print 'var' (see the explaination below) class. The return value is a dictionary that use as key the class name and value an index.

- `d.getMethod(<var>)`      : Print 'var' (see the explaination below) method. The return value is a dictionary that use as key the method name and value an index.

- `d.getString(<var>)`      : Print 'var' (see the explaination below) string. The return value is a dictionary that use as key the string name and value an index.

- `d.getType(<var>)`        : Print 'var' (see the explaination below) type. The return value is a dictionary that use as key the class type and value an index.

The variable ('var') can be a list or primitive types but only an integer or string (also mixed). If you pass a integer the function return the value from that index. If, instead, you pass a string, this function search the name that have 'var' inside (case-insensitive).

## Limitations

This project is in the first stage, so that are a lot of problem and limitations.
Known problem:

1. 'Get' type functions: there can be duplicate key that can possibly substitute the previous value.
2. The 'getString' function does not check "source class" field.
3. The printing method don't show the parameters with invoke bytecode.
4. Printing problem
5. Static field are not initialized
6. The smali code does not diversify parameters and local registers.
7. The application does not allow the read of Android Manifest
8. Debug information are not shown
9. Interface information are not shown.
10. Annotation information are not shown.
11. This tools need a code refactor (for example using multi-thread).

Any help is welcome.
