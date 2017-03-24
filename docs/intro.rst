Introduction
============
The APT Scanner `Thor <https://www.bsk-consulting.de/apt-scanner-thor/>`_ can be extended using yara rules containing
values to search for in registry, mutexes and filepatterns. To be able to quickly export our MISP database regarding
the mentioned values and to create yara rules in the specific Thor format, this tool was created. More information about
Thor yara rule formatting can be obtained in their documentation.

Remember to apply the correct keyword to the file name: ``registry`` for regkey rules and  ``keyword`` for mutex rules
which have ``limit = "Mutex"`` set in the rule itself. Pattern-in-file rules don't need a special filename.

If there are too many false positives, you can always propose attributes to delete, remove the IDS exporting flag or use
the ignore parameter.

Be aware that this tool is more a quick&dirty hack than a complete software.
