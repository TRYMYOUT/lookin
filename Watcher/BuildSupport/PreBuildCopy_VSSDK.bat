@echo off

REM
REM This is the pre-build script for the TFS integration plug-in for Watcher.
REM It attempts to determine the installation location of the Visual Studio
REM 2008 SDK and copies the appropriate assemblies for use in the build.
REM
REM Arguments:
REM %1		Path to which to copy the TFS assemblies
REM

if "%1" == "" (
	echo Usage: %0 path
	echo.
	echo Copy the TFS assemblies to the specified path.
	exit /b
)

if "%VSSDK90Install%" == "" (
	echo Unable to locate the Visual Studio 2008 SDK.
	exit /b 1
)

REM
REM Set up the TFS assembly paths and the path where the assemblies will be
REM copied.
REM
SET TFS_ASSEMBLY_PATH="%VSSDK90Install%VisualStudioIntegration\Common\Assemblies\"
SET OUTPUT_PATH=%1

REM
REM Ensure the destination directory exists
REM
mkdir %OUTPUT_PATH%

REM
REM Enumerate each of the required TFS client assemblies and copy them to the
REM solution's External directory.  These are referenced by the project and
REM will be copied to the Fiddler scripts directory during post-build for
REM debugging purposes.
REM
for %%A in (Microsoft.TeamFoundation.Client.dll Microsoft.TeamFoundation.Common.dll Microsoft.TeamFoundation.dll Microsoft.TeamFoundation.WorkItemTracking.Client.dll) do call :copy %%A
goto :eof

REM
REM Copy the specified file (a TFS assembly from the Visual Studio 2008 SDK) to
REM the solutions's External directory, for reference by the project.
REM
:copy
SET CURRENT_ASSEMBLY="%TFS_ASSEMBLY_PATH:"=%%1"

if not exist %CURRENT_ASSEMBLY% (
	echo Cannot locate the following required assembly:
	echo %CURRENT_ASSEMBLY%
	exit 1
)

echo Copying %1 to %OUTPUT_PATH%...
copy /y %CURRENT_ASSEMBLY% %OUTPUT_PATH%

if %ERRORLEVEL% NEQ 0 (
	echo Error: Cannot copy the assembly to the specified directory.  
	echo Error: Make sure the Microsoft Visual Studio 2008 SDK is installed.  Result: %ERRORLEVEL%
	exit %ERRORLEVEL%
) 
