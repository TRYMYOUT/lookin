;venis.nsi
;MakeNSIS v2.0.5
;Written by Angelo Mandato
;Date: 03/12/2005

;--------------------------------
;Define application defines
!define APPNAME "Venis IX" ;Define your own software name here
!define APPNAMEANDVERSION "${APPNAME} 2.2.5 Free" ;Define your own software version here

;--------------------------------
;Configuration
!include "MUI.nsh"

!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN "$INSTDIR\Venis.exe"
!define MUI_FINISHPAGE_RUN_NOTCHECKED
;Uncomment the following two lines if you wish to recompile the Venis Install Script
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_BITMAP "spaceblue-header4.bmp"

;Install properties
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "license.txt"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

;Uninstall properties
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

;Language
!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_RESERVEFILE_LANGDLL

  
;General Settings
OutFile "VenisIX225free.exe"
Name "${APPNAMEANDVERSION}"
InstallDir "$PROGRAMFILES\Venis"
InstallDirRegKey HKEY_LOCAL_MACHINE SOFTWARE\Venis "Install_Dir"

;License page
LicenseData "License.txt"

;Show install details.
ShowInstDetails show
	
	
;--------------------------------
;Install Types
InstType Typical
InstType Full

;--------------------------------
;Installer Sections

Section "Venis Core" SecVenisCore

	SectionIn 1 2 RO
  SetOutPath "$INSTDIR"
  File "Venis.exe"
  File "Venis.nsi"
  File "functions.vfp"
  File "wordfile.vwf"
	File "nsis.api"
  File "license.txt"
	File "readme.txt"
	File "credits.txt"
	File "history.txt"
	File "Venis.ini"

  WriteRegStr HKEY_CURRENT_USER "SOFTWARE\Spaceblue\${APPNAME}\Preferences" "FunctionsFile" "$INSTDIR\functions.vfp"
  WriteRegStr HKEY_CURRENT_USER "SOFTWARE\Spaceblue\${APPNAME}\Preferences" "WordFile" "$INSTDIR\wordfile.vwf"
	WriteRegStr HKEY_CURRENT_USER "SOFTWARE\Spaceblue\${APPNAME}\Preferences" "ApiFile" "$INSTDIR\nsis.api"
	
	ReadRegStr $0 HKEY_LOCAL_MACHINE SOFTWARE\NSIS ""
	StrCmp $0 "" NoSetNsisPath
		WriteRegStr HKEY_CURRENT_USER "SOFTWARE\Spaceblue\${APPNAME}\Preferences" "NsisPath" "$0\makensis.exe"
		
		; if the nsis.chm file exists, lets use that instead...
		FindFirst $1 $2 "$0\nsis.chm"
		StrCmp $2 "" TrySetNsisHtmlPath
			WriteRegStr HKEY_CURRENT_USER "SOFTWARE\Spaceblue\${APPNAME}\Preferences" "NsisHtmlPath" "$0\nsis.chm"
		
		TrySetNsisHtmlPath:
			FindFirst $1 $2 "$0\makensis.html"
			StrCmp $2 "" NoSetNsisPath
				WriteRegStr HKEY_CURRENT_USER "SOFTWARE\Spaceblue\${APPNAME}\Preferences" "NsisHtmlPath" "$0\makensis.html"
		
	NoSetNsisPath:
	
	WriteRegStr HKEY_CLASSES_ROOT ".ves" "" "VenisSession"
	WriteRegStr HKEY_CLASSES_ROOT "VenisSession" "" "Venis Session File"
	WriteRegStr HKEY_CLASSES_ROOT "VenisSession\shell" "" "open"
	WriteRegStr HKEY_CLASSES_ROOT "VenisSession\DefaultIcon" "" "$INSTDIR\Venis.exe,0"
	WriteRegStr HKEY_CLASSES_ROOT "VenisSession\shell\Venis" "" "Open Venis Session"
	WriteRegStr HKEY_CLASSES_ROOT "VenisSession\shell\Venis\command" "" '"$INSTDIR\Venis.exe" "%1"'
	
	; set for pre NSIS 2.0 release or later installers
  WriteRegStr HKCR "NSISFile\shell\Venis" "" "Edit with Venis IX"
  WriteRegStr HKCR "NSISFile\shell\Venis\command" "" '"$INSTDIR\Venis.exe" "%1"'
	WriteRegStr HKCR "NSHFile\shell\Venis" "" "Edit with Venis IX"
  WriteRegStr HKCR "NSHFile\shell\Venis\command" "" '"$INSTDIR\Venis.exe" "%1"'
	
	; set for NSIS 2.0 release or newer installers
	WriteRegStr HKCR "NSIS.Script\shell\Venis" "" "Edit with Venis IX"
  WriteRegStr HKCR "NSIS.Script\shell\Venis\command" "" '"$INSTDIR\Venis.exe" "%1"'
	WriteRegStr HKCR "NSIS.Header\shell\Venis" "" "Edit with Venis IX"
  WriteRegStr HKCR "NSIS.Header\shell\Venis\command" "" '"$INSTDIR\Venis.exe" "%1"'
   
  ;Write the installation path into the registry
  WriteRegStr HKLM SOFTWARE\Venis "Install_Dir" "$INSTDIR"
	
  ;Write the uninstall keys for Windows
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Venis" "DisplayName" "Venis (remove only)"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Venis" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteUninstaller "uninstall.exe"

SectionEnd

; optional Start menu shortcut section
Section "Start Menu Shortcuts" SecStartMenuShortcuts
	
	SectionIn 1 2
  CreateDirectory "$SMPROGRAMS\Venis"
  CreateShortCut "$SMPROGRAMS\Venis\Uninstall.lnk" "$INSTDIR\uninstall.exe" "" "$INSTDIR\uninstall.exe" 0
	Delete "$SMPROGRAMS\Venis\Venis.lnk" ; Delete older link if exists
  CreateShortCut "$SMPROGRAMS\Venis\Venis IX.lnk" "$INSTDIR\Venis.exe" "" "$INSTDIR\Venis.exe" 0

SectionEnd

; optional Desktop shortcut section
Section "Desktop Shortcut" SecDesktopShortcut
  
	SectionIn 1 2
	; For past users, cleanup previous icon if still on desktop
	Delete "$DESKTOP\Venis.lnk"
  CreateShortCut "$DESKTOP\Venis IX.lnk" "$INSTDIR\Venis.exe" "" "$INSTDIR\Venis.exe" 0

SectionEnd

; optional Desktop shortcut section
Section "Quick Launch Shortcut" SecQuickLaunchShortcut
  
	SectionIn 2
	CreateShortCut "$QUICKLAUNCH\Venis IX.lnk" "$INSTDIR\Venis.exe" "" "$INSTDIR\Venis.exe" 0

SectionEnd

;--------------------------------
;Component Section Descriptions
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecVenisCore} "Venis core files (required)"
	!insertmacro MUI_DESCRIPTION_TEXT ${SecStartMenuShortcuts} "Venis Start Menu Shortcuts"
	!insertmacro MUI_DESCRIPTION_TEXT ${SecDesktopShortcut} "Venis Desktop Shortcut"
	!insertmacro MUI_DESCRIPTION_TEXT ${SecQuickLaunchShortcut} "Venis Quick Launch Shortcut"
!insertmacro MUI_FUNCTION_DESCRIPTION_END
 
;--------------------------------
;Uninstaller Section
Section "Uninstall"

	; Delete all the files in the Venis IX folder.
	; This is ok since we are migrating to saving settings in different
	; locations (registry and application data directory)
	RMDir /r "$INSTDIR" 

	; Delete start menu stuff
  RMDir /r "$SMPROGRAMS\Venis"

  ; Delete desktop icons...
  Delete "$DESKTOP\Venis IX.lnk"
	
	; Delete quicklaunch icon
	Delete "$QUICKLAUNCH\Venis IX.lnk"

  ; Delete other shortcuts
  DeleteRegKey HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\Venis"
  DeleteRegKey HKEY_LOCAL_MACHINE "SOFTWARE\Venis"
  DeleteRegKey HKEY_CURRENT_USER "NSISFile\shell\Venis"
	DeleteRegKey HKEY_CURRENT_USER "NSHFile\shell\Venis"
	DeleteRegKey HKEY_CURRENT_USER "NSIS.Script\shell\Venis"
	DeleteRegKey HKEY_CURRENT_USER "NSIS.Header\shell\Venis"
	DeleteRegKey HKEY_CURRENT_USER "Software\Spaceblue\${APPNAME}"
	
SectionEnd

BrandingText "©2005 Spaceblue LLC"

; eof