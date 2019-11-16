## Bleak 

## Note as of 16/11/2019

This library in its current form is not likely to receive anymore updates in the future, and will likely end up deprecated at some point.

I have started work on a new injection library which alongside new features and better resource usage will be adherring to some very clear standards which I will mention shortly. When I started on Bleak I very much had no experience working on large public projects and so, made some very poor mistakes throughout the development cycle which means offering support for the library (unless everyone was on the latest version) is near impossible.

Which leads me to the new project which will have the following

- A standardised public interface that will not change between versions (asside from potentially adding new methods where warranted)
- Written to always officially support the latest version of Windows (and not worry about previous versions)
- Usage of unsafe code where applicable as a replacement for the various 'hacks' I found myself using with IntPtr's
- Proper OS version checking to ensure the library is not used on platforms that are not supported
- Minimise the usage of resources where possible with the help of the new api's provided by the latest versions of .Net
- Embracing the new design guidelines that the .Net team is using for .Net Core 3 +

I am still deciding what new features I will be adding but the following has been confirmed

- VEH support
- Manual mapping to add references (optionally) to loader structures to allow loaded dll's to be used as if they were loaded by the windows loader
- Manual mapping to support more features i.e. initialising static TLS

I cannot estimate when this new project will be completed as I am quite busy as of lately, however, I have started laying the foundations of the new project and am hoping to get something finished late this year / early next year.

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
