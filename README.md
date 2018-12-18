### SuspiciousMemoryDetect

This is a little tool I wrote for learning purposes. It scans memory for things that are potentially suspicious. Had to implement some "undocumented" ntdll functions, shoutout to https://undocumented.ntinternals.net/.

Here's what it can do..

* Find all open handles to specified process and identify what process opened the handle
* Enumerate all executable pages within the specified process, check if each executable page is mapped to a module, and mark it as suspicious if it is not
* Find all threads within process and scan them for specfied byte signature
* Scan process memory for specified byte signature
