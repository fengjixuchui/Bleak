## Bleak 

![](https://github.com/Akaion/Bleak/workflows/Continuous%20Integration/badge.svg)

A Windows native DLL injection library that supports several methods of injection.

----

### Injection Methods

* CreateThread
* HijackThread
* ManualMap

### Optional Extensions

* EjectDll
* HideDllFromPeb
* RandomiseDllHeaders
* RandomiseDllName

### Features

* WOW64 and x64 injection

----

### Installation

* Download and install Bleak using [NuGet](https://www.nuget.org/packages/Bleak)

----

### Getting Started

After installing Bleak, you will want to ensure that your project is being compiled under AnyCPU or x64. This will ensure that you are able to inject into both WOW64 and x64 processes from the same project.

----

### Usage

The example below describes a basic implementation of the library.

```csharp
using Bleak;

using var injector = new Injector("processName", "dllPath", InjectionMethod.CreateThread, InjectionFlags.None);

// Inject the DLL into the process
	
var dllBaseAddress = injector.InjectDll();
	
// Eject the DLL from the process

injector.EjectDll();
```

----

### Overloads

A process ID can be used instead of a process name.

```csharp
var injector = new Injector(processId, "dllPath", InjectionMethod.CreateThread, InjectionFlags.None);
```

A byte array representing a DLL can be used instead of a DLL path.

```csharp
var injector = new Injector("processName", dllBytes, InjectionMethod.CreateThread, InjectionFlags.None);
```
----

### Caveats

* Attemping to inject into a system level process will require your program to be run in Administrator mode.

* Injecting a byte array (that represents a DLL) will result in a temporary DLL being written to disk in `%temp%`, unless the method of injection is ManualMap, in which case nothing will be written to disk.

* Injecting with the HideDllFromPeb flag will currently result in your DLL not being able to be ejected.

* ManualMap injection supports the intialisation of exception handling, however, this is limited to structured exception handling. Vectored exception handlers are not setup in the remote process during injection and any exceptions being handled using this type of exception handling will not be caught.

* ManualMap injection relies on a PDB being present for ntdll.dll and, so, the first time this method is used, a PDB for ntdll.dll will be downloaded and cached in `%temp%`. Note that anytime your system performs an update, a new version of this PDB may need to be downloaded and re-cached. This process may take a few seconds depending on your connection speed.

----

### Warnings

To those of you that are using the source code of this library as a reference, please note the following.

* Many of the native structure definitions used, particularly the internal ones that are not documented on MSDN are incomplete due to only specific members being referenced in the codebase.

* Unsigned members of the native structures used have been changed to signed members to ensure CLS compliance.

----

### Contributing

Pull requests are welcome. 

For large changes, please open an issue first to discuss what you would like to add.
