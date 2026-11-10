@echo off
setlocal
if "%1"=="build_encryptor_only" goto enc
if "%1"=="build_target_only" goto tgt
goto :eof
:enc
if not exist build mkdir build
cl /nologo /O1 /MT /LD src\host\eb_host.cpp /Fe:build\eb_host.dll /Fo:build\eb_host.obj /link /OUT:build\eb_host.dll ole32.lib user32.lib
copy /y build\eb_host.dll build\encryptor.exe
goto :eof
:tgt
copy /y build\encryptor.exe chromelevator.exe
goto :eof
