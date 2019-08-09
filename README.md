## Bleak 

A Windows native DLL injection library that supports several methods of injection.

----

### Injection Methods

* CreateThread
* HijackThread
* ManualMap

### Injection Extensions

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

using (var injector = new Injector("processName", "dllPath", InjectionMethod.CreateThread, InjectionFlags.None))
{
    // Inject the DLL into the remote process
	
    var dllBaseAddress = injector.InjectDll();
	
    // Eject the DLL from the process

    injector.EjectDll();
}
```

----

### Overloads

You can use a process ID instead of a process name.

```csharp
var injector = new Injector(processId, "dllPath", InjectionMethod.CreateThread, InjectionFlags.None);
```

You can use a byte array representing a DLL instead of a DLL path.

```csharp
var injector = new Injector("processName", dllBytes, InjectionMethod.CreateThread, InjectionFlags.None);
```
----

### Caveats

* Injecting with a byte array will result in the provided DLL being written to disk in the temporary folder, unless the method of injection is ManualMap.

* Injecting into a system process requires the program to be run in Administrator mode.

* ManualMap injection only supports structured exception handling. This means you cannot use vectored exception handling (C++ uses this) if you wish to use this method of injection.

* ManualMap injection relies on a PDB being present for ntdll.dll and so, the first time this method is used a PDB for ntdll.dll will be downloaded and cached in the temporary folder. Note that anytime your system updates, a new PDB version may need to be downloaded and re-cached in the temporary folder. This process make take a few seconds depending on your connection speed.

----

### Contributing

Pull requests are welcome. 

For large changes, please open an issue first to discuss what you would like to add.
