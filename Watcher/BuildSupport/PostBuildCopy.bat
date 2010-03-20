@echo off

REM
REM This is the post-build script for the Watcher project.  It invokes the COPY
REM command with the given arguments, assumed to be paths to the new builds of
REM the Watcher binaries.
REM
REM Its main purpose is to place the latest build for debugging, and secondly,
REM to display a common reason for the copy failing, which is likely related to
REM an instance of Fiddler already running.
REM
REM
REM Arguments:
REM %1 .. %9      Path to file(s) to copy
REM

REM
REM This is the directory where the files specified on the command line will be placed.
REM
SET CASABA_OUTPATH=%USERPROFILE%\Documents\Fiddler2\Scripts\

if "%~1" == "" (
	echo Usage: %0 file [file] [file] ...
	echo.
	echo Copy the specified files to %CASABA_OUTPATH%.
	goto :eof
)

for %%A in (%*) DO (
	echo Copying "%%~A" to "%CASABA_OUTPATH%"...
	copy /y "%%~A" "%CASABA_OUTPATH%"

	if %ERRORLEVEL% NEQ 0 (
		echo Error: Cannot copy the latest Watcher build to the Fiddler scripts directory.  
		echo Error: Make sure Fiddler is not running prior to copying.  Result: %ERRORLEVEL%
		exit /b %ERRORLEVEL%
	)
)
