@echo off

REM
REM This is the installer creation script for the Watcher project.  It invokes the
REM NSIS installer to create the main Watcher installer, 7-Zip to create a ZIP of
REM the TFS plugin, and md5deep to create SHA256 hashes of the distributables.
REM
REM TODO: Once the installers have been created, remove the object and binary
REM dirs and create a source ZIP: for /f "usebackq delims==" %i in (`dir /s /b bin obj`); do rmdir /s /q "%i"

set CASABA_SHACMD=..\public\md5deep\sha256deep.exe -b
set CASABA_ZIPCMD=..\public\7-Zip\7za.exe a -tzip
set CASABA_NSISCMD=..\public\NSIS\makensis.exe 
set CASABA_OUTDIR=..\Release

REM Create the output directory for the installer files
REM
mkdir %CASABA_OUTDIR%

REM Create the wizard-based, executable installer
REM
%CASABA_NSISCMD% Watcher\installer.nsi
if %ERRORLEVEL% NEQ 0 (
	echo Error: Failed to create Watcher installer.
	echo Error: Ensure Watcher has been built in Release mode.
	exit /b %ERRORLEVEL%
)
%CASABA_SHACMD% %CASABA_OUTDIR%\WatcherSetup.exe > %CASABA_OUTDIR%\WatcherSetup.exe.sha256
if %ERRORLEVEL% NEQ 0 (
	echo Error: Failed to create Watcher installer hash.
	exit /b %ERRORLEVEL%
)

REM Create the binary-only zipped release
REM
%CASABA_ZIPCMD% %CASABA_OUTDIR%\Watcher.zip ..\LICENSE.TXT .\Watcher\EULA.TXT ..\README.TXT ..\CHANGELOG.TXT ..\Watcher\bin\Release\CasabaSecurity.Web.Watcher.dll "..\Watcher Check Library\bin\Release\CasabaSecurity.Web.Watcher.Checks.dll"
if %ERRORLEVEL% NEQ 0 (
	echo Error: Failed to create Watcher zip file.
	echo Error: Ensure Watcher has been built in Release mode.
	exit /b %ERRORLEVEL%
)
%CASABA_SHACMD% %CASABA_OUTDIR%\Watcher.zip > %CASABA_OUTDIR%\Watcher.zip.sha256
if %ERRORLEVEL% NEQ 0 (
	echo Error: Failed to create Watcher zip file hash.
	exit /b %ERRORLEVEL%
)

REM Create the binary-only zipped TFS plugin release
REM
%CASABA_ZIPCMD% %CASABA_OUTDIR%\WatcherTFS.zip ..\LICENSE.TXT .\Plugins\EULA.TXT "..\Watcher Plugins\Team Foundation Server\INSTALL.TXT" "..\Watcher Plugins\Team Foundation Server\Watcher.TeamFoundation.xml" "..\Watcher Plugins\Team Foundation Server\bin\Release\CasabaSecurity.Web.Watcher.TeamFoundation.dll"
if %ERRORLEVEL% NEQ 0 (
	echo Error: Failed to create WatcherTFS zip file.
	echo Error: Ensure the Watcher TFS plugin has been built in Release mode.
	exit /b %ERRORLEVEL%
)
%CASABA_SHACMD% %CASABA_OUTDIR%\WatcherTFS.zip > %CASABA_OUTDIR%\WatcherTFS.zip.sha256
if %ERRORLEVEL% NEQ 0 (
	echo Error: Failed to create Watcher zip file hash.
	exit /b %ERRORLEVEL%
)
