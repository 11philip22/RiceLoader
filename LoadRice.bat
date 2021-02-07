cd ..\DLL2UUID

python PE2SH2UUID.py -f main -fh C:\Users\Philip\source\repos\DllShellSimple\Release\DllShellSimple.dll
copy C:\Users\Philip\source\repos\DllShellSimple\Release\DllShellSimple.h ..\Loader\Payload.h