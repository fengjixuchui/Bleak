using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using Bleak.Assembly;
using Bleak.Memory;
using Bleak.ProgramDatabase;
using Bleak.RemoteProcess.Objects;
using Bleak.Shared;
using Bleak.Shared.Handlers;
using static Bleak.Native.Enumerations;
using static Bleak.Native.PInvoke;
using static Bleak.Native.Structures;

namespace Bleak.RemoteProcess
{
    internal class ProcessManager : IDisposable
    {
        internal readonly bool IsWow64;

        internal readonly List<Module> Modules;
        
        internal readonly Peb Peb;
        
        internal readonly Process Process;
        
        private readonly Assembler _assembler;
        
        private readonly Dictionary<string, IntPtr> _functionAddressCache;
        
        private readonly MemoryManager _memoryManager;
        
        private readonly Lazy<PdbParser> _pdbParser;
        
        internal ProcessManager(int processId)
        {
            Process = GetProcess(processId);

            IsWow64 = IsProcessWow64();

            _memoryManager = new MemoryManager(Process.SafeHandle);
            
            Peb = GetPeb();
            
            Modules = GetModules();

            _assembler = new Assembler(IsWow64);
            
            _functionAddressCache = new Dictionary<string, IntPtr>();
            
            _pdbParser = new Lazy<PdbParser>(() => new PdbParser(Modules.Find(module => module.Name == "ntdll.dll")));
            
            EnableDebuggerPrivileges();
        }
        
        internal ProcessManager(string processName)
        {
            Process = GetProcess(processName);

            IsWow64 = IsProcessWow64();

            _memoryManager = new MemoryManager(Process.SafeHandle);
            
            Peb = GetPeb();

            Modules = GetModules();
            
            _assembler = new Assembler(IsWow64);

            _functionAddressCache = new Dictionary<string, IntPtr>();
            
            _pdbParser = new Lazy<PdbParser>(() => new PdbParser(Modules.Find(module => module.Name == "ntdll.dll")));
            
            EnableDebuggerPrivileges();
        }
        
        public void Dispose()
        {
            Process.Dispose();
        }

        internal void CallFunction(CallingConvention callingConvention, IntPtr functionAddress, params ulong[] parameters)
        {
            // Write the shellcode used to call the function into the remote process

            var shellcode = _assembler.AssembleFunctionCall(callingConvention, functionAddress, IntPtr.Zero, parameters);

            var shellcodeBuffer = _memoryManager.AllocateVirtualMemory(shellcode.Length);
            
            _memoryManager.WriteVirtualMemory(shellcodeBuffer, shellcode);
            
            // Create a thread to call the shellcode in the remote process
            
            var ntStatus = RtlCreateUserThread(Process.SafeHandle, IntPtr.Zero, false, 0, IntPtr.Zero, IntPtr.Zero, shellcodeBuffer, IntPtr.Zero, out var threadHandle, IntPtr.Zero); 
            
            if (ntStatus != NtStatus.Success)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to create a thread in the remote process");
            }

            WaitForSingleObject(threadHandle, int.MaxValue);
            
            threadHandle.Dispose();
            
            _memoryManager.FreeVirtualMemory(shellcodeBuffer);
        }
        
        internal TStructure CallFunction<TStructure>(CallingConvention callingConvention, IntPtr functionAddress, params ulong[] parameters) where TStructure : struct
        {
            // Allocate a buffer in the remote process to store the returned value of the function

            var returnBuffer = _memoryManager.AllocateVirtualMemory(Marshal.SizeOf<TStructure>());
            
            // Write the shellcode used to call the function into the remote process

            var shellcode = _assembler.AssembleFunctionCall(callingConvention, functionAddress, returnBuffer, parameters);

            var shellcodeBuffer = _memoryManager.AllocateVirtualMemory(shellcode.Length);
            
            _memoryManager.WriteVirtualMemory(shellcodeBuffer, shellcode);
            
            // Create a thread to call the shellcode in the remote process

            var ntStatus = NtCreateThreadEx(out var threadHandle, ThreadAccessMask.AllAccess, IntPtr.Zero, Process.SafeHandle, shellcodeBuffer, IntPtr.Zero, ThreadCreationFlags.HideFromDebugger, 0, 0, 0, IntPtr.Zero);
            
            //var ntStatus = RtlCreateUserThread(Process.SafeHandle, IntPtr.Zero, false, 0, IntPtr.Zero, IntPtr.Zero, shellcodeBuffer, IntPtr.Zero, out var threadHandle, IntPtr.Zero); 
            
            if (ntStatus != NtStatus.Success)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to create a thread in the remote process");
            }

            WaitForSingleObject(threadHandle, int.MaxValue);
            
            threadHandle.Dispose();
            
            _memoryManager.FreeVirtualMemory(shellcodeBuffer);
            
            try
            {
                // Read the returned value of the function from the buffer

                return _memoryManager.ReadVirtualMemory<TStructure>(returnBuffer);
            }

            finally
            {
                _memoryManager.FreeVirtualMemory(returnBuffer);
            }
        }
        
        internal IntPtr GetFunctionAddress(string moduleName, string functionName)
        {
            if (_functionAddressCache.TryGetValue(functionName, out var functionAddress))
            {
                return functionAddress;
            }
            
            // Search the module list of the process for the specified module
            
            var processModule = Modules.Find(module => module.Name.Equals(moduleName, StringComparison.OrdinalIgnoreCase));

            if (processModule is null)
            {
                return IntPtr.Zero;
            }
            
            // Calculate the address of the function

            var function = processModule.PeParser.Value.ExportedFunctions.Find(exportedFunction => exportedFunction.Name != null && exportedFunction.Name == functionName);

            functionAddress = processModule.BaseAddress.AddOffset(function.Offset);
            
            // Calculate the start and end address of the export directory
            
            var exportDirectory = processModule.PeParser.Value.PeHeaders.PEHeader.ExportTableDirectory;
            
            var exportDirectoryStartAddress = processModule.BaseAddress.AddOffset(exportDirectory.RelativeVirtualAddress);
            
            var exportDirectoryEndAddress = exportDirectoryStartAddress.AddOffset(exportDirectory.Size);
            
            // Check if the function is forwarded to another function

            if ((ulong) functionAddress < (ulong) exportDirectoryStartAddress || (ulong) functionAddress > (ulong) exportDirectoryEndAddress)
            {
                _functionAddressCache.Add(functionName, functionAddress);
                
                return functionAddress;
            }
            
            // Read the forwarded function
            
            var forwardedFunctionBytes = new List<byte>();

            while (true)
            {
                var currentByte = _memoryManager.ReadVirtualMemory(functionAddress, 1);

                if (currentByte[0] == 0x00)
                {
                    break;
                }

                forwardedFunctionBytes.Add(currentByte[0]);

                functionAddress += 1;
            }
            
            var forwardedFunction = Encoding.Default.GetString(forwardedFunctionBytes.ToArray()).Split('.');

            return GetFunctionAddress(forwardedFunction[0] + ".dll", forwardedFunction[1]);
        }

        internal IntPtr GetFunctionAddress(string moduleName, ushort? functionOrdinal)
        {
            // Search the module list of the process for the specified module
            
            var processModule = Modules.Find(module => module.Name.Equals(moduleName, StringComparison.OrdinalIgnoreCase));

            if (processModule is null)
            {
                return IntPtr.Zero;
            }
            
            // Get the name of the function
            
            var function = processModule.PeParser.Value.ExportedFunctions.Find(exportedFunction => exportedFunction.Ordinal == functionOrdinal);

            return GetFunctionAddress(moduleName, function.Name);
        }
        
        internal IEnumerable<PebEntry> GetPebEntries()
        {
            if (IsWow64)
            {
                // Read the loader data of the WOW64 PEB

                var pebLoaderData = _memoryManager.ReadVirtualMemory<PebLdrData32>(Peb.LoaderAddress);

                var currentPebEntryAddress = pebLoaderData.InLoadOrderModuleList.Flink;

                while (true)
                {
                    // Read the current entry from the InLoadOrder linked list

                    var loaderEntry = _memoryManager.ReadVirtualMemory<LdrDataTableEntry32>((IntPtr) currentPebEntryAddress);

                    yield return new PebEntry(loaderEntry);

                    if (currentPebEntryAddress == pebLoaderData.InLoadOrderModuleList.Blink)
                    {
                        break;
                    }

                    // Get the address of the next entry in the InLoadOrder linked list

                    currentPebEntryAddress = loaderEntry.InLoadOrderLinks.Flink;
                }
            }

            else
            {
                // Read the loader data of the PEB
            
                var pebLoaderData = _memoryManager.ReadVirtualMemory<PebLdrData64>(Peb.LoaderAddress);

                var currentPebEntryAddress = pebLoaderData.InLoadOrderModuleList.Flink;

                while (true)
                {
                    // Read the current entry from the InLoadOrder linked list

                    var loaderEntry = _memoryManager.ReadVirtualMemory<LdrDataTableEntry64>((IntPtr) currentPebEntryAddress);

                    yield return new PebEntry(loaderEntry);

                    if (currentPebEntryAddress == pebLoaderData.InLoadOrderModuleList.Blink)
                    {
                        break;
                    }

                    // Get the address of the next entry in the InLoadOrder linked list

                    currentPebEntryAddress = loaderEntry.InLoadOrderLinks.Flink;
                }
            }
        }
        
        internal IntPtr GetSymbolAddress(string symbolName)
        {
            var pdbSymbol = _pdbParser.Value.PdbSymbols.Find(symbol => symbol.Name == symbolName);
            
            // Get the section that the symbol resides in

            var symbolSection = _pdbParser.Value.Module.PeParser.Value.PeHeaders.SectionHeaders[(int) pdbSymbol.Section - 1];
            
            // Calculate the address of the symbol

            return _pdbParser.Value.Module.BaseAddress.AddOffset(symbolSection.VirtualAddress + pdbSymbol.Offset);
        }
        
        internal void Refresh()
        {
            Modules.Clear();
            
            Modules.AddRange(GetModules());
            
            Process.Refresh();
        }
        
        private void EnableDebuggerPrivileges()
        {
            try
            {
                Process.EnterDebugMode();
            }

            catch (Win32Exception)
            {
                // The local process isn't running in administrator mode
            }
        }
        
        private List<Module> GetModules()
        {
            var modules = new List<Module>();

            var filePathRegex = new Regex("System32", RegexOptions.IgnoreCase);
            
            foreach (var pebEntry in GetPebEntries())
            {
                if (!Environment.Is64BitProcess || IsWow64)
                {
                    var loaderEntry = (LdrDataTableEntry32) pebEntry.LoaderEntry;
                    
                    // Read the file path of the entry

                    var entryFilePathBytes = _memoryManager.ReadVirtualMemory((IntPtr) loaderEntry.FullDllName.Buffer, loaderEntry.FullDllName.Length);

                    var entryFilePath = filePathRegex.Replace(Encoding.Unicode.GetString(entryFilePathBytes), "SysWOW64");

                    // Read the name of the entry

                    var entryNameBytes = _memoryManager.ReadVirtualMemory((IntPtr) loaderEntry.BaseDllName.Buffer, loaderEntry.BaseDllName.Length);

                    var entryName = Encoding.Unicode.GetString(entryNameBytes);

                    modules.Add(new Module((IntPtr) loaderEntry.DllBase, entryFilePath, entryName));
                }

                else
                {
                    var loaderEntry = (LdrDataTableEntry64) pebEntry.LoaderEntry;
                    
                    // Read the file path of the entry

                    var entryFilePathBytes = _memoryManager.ReadVirtualMemory((IntPtr) loaderEntry.FullDllName.Buffer, loaderEntry.FullDllName.Length);

                    var entryFilePath = Encoding.Unicode.GetString(entryFilePathBytes);

                    // Read the name of the entry

                    var entryNameBytes = _memoryManager.ReadVirtualMemory((IntPtr) loaderEntry.BaseDllName.Buffer, loaderEntry.BaseDllName.Length);

                    var entryName = Encoding.Unicode.GetString(entryNameBytes);

                    modules.Add(new Module((IntPtr) loaderEntry.DllBase, entryFilePath, entryName));
                }
            }

            return modules;
        }
        
        private Peb GetPeb()
        {
            if (IsWow64)
            {
                // Query the remote process for the address of the WOW64 PEB

                var pebAddressBuffer = Marshal.AllocHGlobal(sizeof(ulong));

                if (NtQueryInformationProcess(Process.SafeHandle, ProcessInformationClass.Wow64Information, pebAddressBuffer, sizeof(ulong), IntPtr.Zero) != NtStatus.Success)
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to query the remote process for the address of the WOW64 PEB");
                }
                
                var pebAddress = Marshal.PtrToStructure<ulong>(pebAddressBuffer);

                Marshal.FreeHGlobal(pebAddressBuffer);

                // Read the WOW64 PEB of the remote process

                var peb = _memoryManager.ReadVirtualMemory<Peb32>((IntPtr) pebAddress);

                return new Peb((IntPtr) peb.ApiSetMap, (IntPtr) peb.Ldr);
            }

            else
            {
                // Query the remote process for its basic information

                var basicInformationSize = Marshal.SizeOf<ProcessBasicInformation>();

                var basicInformationBuffer = Marshal.AllocHGlobal(basicInformationSize);

                if (NtQueryInformationProcess(Process.SafeHandle, ProcessInformationClass.BasicInformation, basicInformationBuffer, basicInformationSize, IntPtr.Zero) != NtStatus.Success)
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to query the remote process for its basic information");
                }

                var basicInformation = Marshal.PtrToStructure<ProcessBasicInformation>(basicInformationBuffer);

                Marshal.FreeHGlobal(basicInformationBuffer);

                // Read the PEB of the remote process

                var peb = _memoryManager.ReadVirtualMemory<Peb64>(basicInformation.PebBaseAddress);

                return new Peb((IntPtr) peb.ApiSetMap, (IntPtr) peb.Ldr);
            }
        }
        
        private Process GetProcess(int processId)
        {
            try
            {
                return Process.GetProcessById(processId);
            }

            catch (ArgumentException)
            {
                throw new ArgumentException($"No process with the id {processId} is currently running");
            }
        }
        
        private Process GetProcess(string processName)
        {
            try
            {
                return Process.GetProcessesByName(processName)[0];
            }

            catch (IndexOutOfRangeException)
            {
                throw new ArgumentException($"No process with the name {processName} is currently running");
            }
        }
        
        private bool IsProcessWow64()
        {
            if (!IsWow64Process(Process.SafeHandle, out var isWow64Process))
            {
                ExceptionHandler.ThrowWin32Exception("Failed to determine whether the remote process was running under WOW64");
            }

            return isWow64Process;
        }
    }
}