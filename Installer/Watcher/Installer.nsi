; Install using the current user permissions
RequestExecutionLevel "admin"

; Preprocessor definitions
!define PUBLISHER "Casaba Security, LLC."
!define APPNAME "Watcher Web Security Tool"
!define APPVERSION "1.5.8"
!define ICONPATH "..\..\Watcher\Resources\WatcherInstaller.ico"

; Locations where previous versions of Watcher may be installed (not
; exhaustive--just the default locations).
!define FIDDLERSCRIPTDIR1 "C:\Program Files\Fiddler2\Scripts"
!define FIDDLERSCRIPTDIR2 "C:\Program Files (x86)\Fiddler2\Scripts"
!define FIDDLERSCRIPTDIR3 "$DOCUMENTS\Fiddler2\Scripts"

; Installer branding information
VIAddVersionKey "ProductName" "Watcher Web Security Tool"
VIAddVersionKey "CompanyName" "Casaba Security, LLC"
VIAddVersionKey "LegalCopyright" "Copyright © 2010 Casaba Security, LLC"
VIAddVersionKey "FileDescription" "Watcher Web Security Extension for Fiddler Web Debugging Proxy"
VIAddVersionKey "FileVersion" "${APPVERSION}.0"
VIAddVersionKey "ProductVersion" "${APPVERSION}.0"
VIProductVersion ${APPVERSION}.0

; Text shown at the bottom of the installer window
BrandingText " "

; Name of the installer application
OutFile "..\..\Release\WatcherSetup.exe"

; Name of the application and the install/uninstall icon
Name "${APPNAME} v${APPVERSION}"
Icon ${ICONPATH}
UninstallIcon ${ICONPATH}

; License Agreement
LicenseData "EULA.TXT"
LicenseText "If you accept the terms of the agreement, click I Agree to continue.  You must accept the agreement to install ${APPNAME}."

; Install to the current user's documents directory (default)
InstallDir "$DOCUMENTS\Fiddler2\Scripts"
DirText "Choose the folder in which to install ${APPNAME} v${APPVERSION}."

Section "Watcher Web Security Tool"

	; Remove the previous version of the product, if installed
	Call UninstallPreviousVersion

	; Overwrite output files
	SetOverwrite on

	; Set the output path and the files to include in the installer
	SetOutPath "$INSTDIR\"
	File "..\..\Watcher Check Library\bin\Release\CasabaSecurity.Web.Watcher.dll"
	File "..\..\Watcher Check Library\bin\Release\CasabaSecurity.Web.Watcher.Checks.dll"

SectionEnd

; Complete the installation by registering the product's uninstall information
Section -FinishInstallationSection

	DetailPrint "Creating uninstall information..."

	; Technically, this would be where settings would be placed if we were
	; using the registry to store them.
	WriteRegStr HKLM "Software\CasabaSecurity\${APPNAME}" "" "$INSTDIR"

	; Register the uninstallation information
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "DisplayName" "${APPNAME}"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "DisplayVersion" "${APPVERSION}"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "Publisher" "${PUBLISHER}"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "DisplayIcon" "$INSTDIR\uninstall.exe"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "UninstallString" "$INSTDIR\uninstall.exe"

	; Create the uninstaller
	WriteUninstaller "$INSTDIR\uninstall.exe"

SectionEnd

; Remove the previous version of the product, if installed.
; Also, remove any deprecated assembly names that appear before v1.2.0 to prevent conflicts.
Function UninstallPreviousVersion

	DetailPrint "Checking for previous installation of ${APPNAME}..."

	; Run the installer for the last version of the product installed, if
	; it exists
	ClearErrors
	ReadRegStr $0 HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "UninstallString"
	IfErrors Skip1 0
		DetailPrint "Uninstalling previous installation of ${APPNAME} via $0..."
		ExecWait '"$0" _?=$INSTDIR' $1
		IntCmp $1 0 Removed NotRemoved NotRemoved
		NotRemoved:
			DetailPrint "Previous installation NOT removed: cannot continue."
			Quit
		Removed:
			DetailPrint "Previous installation removed."
		Skip1:

	; Remove the "old style" assembly names, if they exist
	DetailPrint "Checking for conflicting assembly names (names prior to v1.2.0)..."

	; Check for older versions of Watcher in the Fiddler2 script path
	ClearErrors
	ReadRegStr $0 HKLM "Software\Microsoft\Fiddler2" "LMScriptPath"
	IfErrors Skip2 0
		DetailPrint "Found Fiddler2 installation."
		DetailPrint "Removing conflicting assemblies from Fiddler2 script location $0..."
		Delete "$0\Watcher.dll"
		Delete "$0\WatcherCheckLib.dll"
		Skip2:

	DetailPrint "Removing conflicting assemblies from other potential locations..."

	ClearErrors
	DetailPrint "Removing conflicting assemblies from ${FIDDLERSCRIPTDIR1}..."
	Delete "${FIDDLERSCRIPTDIR1}\Watcher.dll"
	Delete "${FIDDLERSCRIPTDIR1}\WatcherCheckLib.dll"

	ClearErrors
	DetailPrint "Removing conflicting assemblies from ${FIDDLERSCRIPTDIR2}..."
	Delete "${FIDDLERSCRIPTDIR2}\Watcher.dll"
	Delete "${FIDDLERSCRIPTDIR2}\WatcherCheckLib.dll"

	ClearErrors
	DetailPrint "Removing conflicting assemblies from ${FIDDLERSCRIPTDIR3}..."
	Delete "${FIDDLERSCRIPTDIR3}\Watcher.dll"
	Delete "${FIDDLERSCRIPTDIR3}\WatcherCheckLib.dll"

FunctionEnd

; Uninstall Section
Section Uninstall

	DetailPrint "Uninstalling ${APPNAME}..."

	; Auto-close the uninstall window when complete
	SetAutoClose true

	; Remove registry entries
	DeleteRegKey HKLM "Software\${APPNAME}"
	DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}"

	; Delete self
	Delete "$INSTDIR\uninstall.exe"

	; Clean up Watcher Check Library
	Delete "$INSTDIR\CasabaSecurity.Web.Watcher.dll"
	Delete "$INSTDIR\CasabaSecurity.Web.Watcher.Checks.dll"

SectionEnd

; Uninstallation initialization
Function un.onInit

	MessageBox MB_YESNO|MB_DEFBUTTON2|MB_ICONQUESTION "Remove ${APPNAME} v${APPVERSION} and all of its components?" IDYES DoUninstall
		Abort
	DoUninstall:

FunctionEnd

; eof
