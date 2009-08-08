@echo off

REM
REM This is the post-build script for the Watcher project.  It invokes the COPY
REM command with the given arguments, assumed to be paths to the new build of
REM Watcher and the version of Watcher to replace, respectively.  
REM
REM Its main purpose is to display a common reason for the copy failing, which 
REM is likely related to an instance of Fiddler already running.
REM
REM Arguments:
REM %1		Path to DLL to copy
REM %2		Path to the DLL destination (Fiddler scripts directory)
REM %3		Path to the Watch Check Library solution directory
REM

copy /y %1 %2
if %ERRORLEVEL% NEQ 0 (
	echo Error: CheckLibPostBuild: Cannot copy latest Watcher Check Library to Fiddler scripts directory.  Make sure Fiddler is not running prior to copying.  Result: %ERRORLEVEL%
)
REM cmd.exe $(SolutionDir)Createinstaller.bat
