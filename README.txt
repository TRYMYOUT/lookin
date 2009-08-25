Casaba Watcher Web Security Tool
---------------------------------------
Copyright (c) 2009, Casaba Security, LLC.
All rights reserved.

A free, passive security testing and auditing tool for web-applications. Watcher enables pen-testing and compliance auditing (e.g., PCI and HIPPA) for web applications.


INSTALLATION
---------------------------------------
Install the Fiddler tool from http://www.fiddlertool.com/. Fiddler must be run at least once before installing Watcher.

Two installation methods are available, running the installer or manual installation.

1. Run the installer package and choose to install for yourself or all users.

2. For a manual installation, copy the CasabaSecurity.Web.Watcher.dll and CasabaSecurity.Web.Watcher.Checks.dll into Fiddler's 'scripts' folder:

On Windows XP flavors: Copy CasabaSecurity.Web.Watcher.dll and CasabaSecurity.Web.Watcher.Checks.dll to %userprofile%\My Documents\Fiddler2\Scripts

On Windows Vista flavors: Copy CasabaSecurity.Web.Watcher.dll and CasabaSecurity.Web.Watcher.Checks.dll to %userprofile%\Documents\Fiddler2\Scripts

UPGRADING
---------------------------------------
Close Fiddler, if it's open during upgrading then the old Watcher files will not be removed, and the new ones might not be installed.  In most cases, you can upgrade by following the INSTALLATION notes above.  However it's sometimes necessary to manually remove the old DLL files from the locations you installed them too.  

If you open Fiddler and see two tabs for Watcher, then you'll need to remove the old DLL's.


UNINSTALLATION
---------------------------------------
You can manually delete the Watcher DLL files from the locations you installed them during the INSTALLATION process.


CONFIGURATION AND USE 
---------------------------------------
Requires typing in the origin domain to monitor and clicking "Enable". Wildcards are supported so *.google.com will work, or simply *. However, wildcards extend the scope of the "cross-domain" checks which will get missed. You can also add "trusted domains™" to exempt them from the cross-domain checks. Some examples of domain configurations:

www.nottrusted.com
// A specific fully qualified domain name is the most precise way to configure Watcher, and will ensure all cross-domain checks.  This provides the best coverage of cross-domain issues, since domains that aren't www.casabasecurity.com will be considered untrusted.

*.casabasecurity.com 
// Any subdomain of .casabasecurity.com will be observed.  This provides good coverage of cross-domain issues, since domains that aren't subdomains of casabasecurity.com' will be considered untrusted.

casaba
// Any domain or subdomain containing 'casaba' will be observed.  This provides decent coverage of cross-domain issues, since domains that don't contain 'casaba' will be considered untrusted.

* 
// all domains will be observed, however cross-domain issues will not be found since * assumes they're all trusted origin domains.  This doesn't provide any coverage of cross-domain issues.

This makes it easy to test when your application has interactions with many subdomains off your own. However, to find cross-domain issues common to mashups, advertising, and other third-party resources, it's better to specify the specific domain.

WATCHER CHECK CONFIGURATIONS
---------------------------------------
Some checks have their own configuration options.  By selecting a check, configurable options will be revealed in the lower pane.

OWASP ASVS COMPLIANCE
---------------------------------------
Watcher provides checks that comply with OWASP's Application Security Verification Standard Levels 1 (ASVL1) and Level 2 (ASVL2).  This is documented inside the Watcher user interface, and also here:

V8.9  ASVL1,ASVL2	Identify Web server error messages.		
V8.9  ASVL1,ASVL2	Identify database error messages.
V9.2  ASVL2		Identify proper use of the Cache-Control headers.
V9.5  ASVL2		Identify sensitive information disclosure in URL.
V9.5  ASVL2		Identify sensitive information disclosure in HTTP headers.
V10.5 ASVL1,ASVL2	Identify SSL certificate validation errors.
V11.2 ASVL2		Identify cookies without the 'secure' flag set.
V11.1 ASVL2		Identify cookies without the 'httponly' flag set.
V11.5 ASVL1,ASVL2	Identify open redirects.

By listing ASVL1 or ASVL2, we're considering that Watcher provides coverage for whatever the requirement calls for, be it Level 1A or Level 2A.

UPDATES
---------------------------------------
You can always obtain the latest version of Watcher from:

http://www.casabasecurity.com/
http://websecuritytool.codeplex.com/
