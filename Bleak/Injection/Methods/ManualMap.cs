using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Text;
using Bleak.Exceptions;
using Bleak.Native.Enumerations;
using Bleak.Memory;
using Bleak.Native;
using Bleak.Native.Structures;

namespace Bleak.Injection.Methods
{
    internal class ManualMap : InjectionBase
    {
        private IntPtr _localDllAddress;

        public ManualMap(byte[] dllBytes, Process process, InjectionFlags injectionFlags) : base(dllBytes, process, injectionFlags) { }

        public ManualMap(string dllPath, Process process, InjectionFlags injectionFlags) : base(dllPath, process, injectionFlags) { }

        internal override void Eject()
        {
            // Call the entry point of the DLL with DllProcessDetach

            if (!ProcessManager.CallFunction<bool>(CallingConvention.StdCall, DllBaseAddress + PeImage.PeHeaders.PEHeader.AddressOfEntryPoint, (long) DllBaseAddress, Constants.DllProcessDetach, 0))
            {
                throw new RemoteFunctionCallException("Failed to call the entry point of the DLL");
            }

            // Remove the entry for the DLL from the LdrpInvertedFunctionTable

            var rtRemoveInvertedFunctionTableAddress = ProcessManager.PdbFile.Value.Symbols["RtlRemoveInvertedFunctionTable"];

            ProcessManager.CallFunction(CallingConvention.FastCall, rtRemoveInvertedFunctionTableAddress, (long) DllBaseAddress);

            // Decrease the reference count of the DLL dependencies

            var freeLibraryAddress = ProcessManager.GetFunctionAddress("kernel32.dll", "FreeLibrary");

            if (PeImage.ImportedFunctions.GroupBy(importedFunction => importedFunction.Dll).Select(dll => ProcessManager.Modules.Find(module => module.Name.Equals(dll.Key, StringComparison.OrdinalIgnoreCase)).BaseAddress).Any(dependencyAddress => !ProcessManager.CallFunction<bool>(CallingConvention.StdCall, freeLibraryAddress, (long) dependencyAddress)))
            {
                throw new RemoteFunctionCallException("Failed to call FreeLibrary");
            }

            // Free the memory allocated for the DLL

            MemoryManager.FreeVirtualMemory(ProcessManager.Process.SafeHandle, DllBaseAddress);
        }

        internal override void Inject()
        {
            // Store the DLL in the local process

            _localDllAddress = Marshal.AllocHGlobal(DllBytes.Length);

            Marshal.Copy(DllBytes, 0, _localDllAddress, DllBytes.Length);

            // Allocate memory for the DLL in the remote process

            try
            {
                DllBaseAddress = MemoryManager.AllocateVirtualMemory(ProcessManager.Process.SafeHandle, (IntPtr) PeImage.PeHeaders.PEHeader.ImageBase, PeImage.PeHeaders.PEHeader.SizeOfImage, MemoryProtectionType.ReadWrite);
            }

            catch (PInvokeException)
            {
                DllBaseAddress = MemoryManager.AllocateVirtualMemory(ProcessManager.Process.SafeHandle, IntPtr.Zero, PeImage.PeHeaders.PEHeader.SizeOfImage, MemoryProtectionType.ReadWrite);
            }

            // Build the import table of the DLL in the local process

            BuildImportTable();

            // Relocate the DLL in the local process

            RelocateImage();

            // Map the sections of the DLL into the remote process

            MapSections();

            // Map the headers of the DLL into the remote process

            MapHeaders();

            // Enable exception handling within the DLL

            EnableExceptionHandling();

            // Call the init routines

            CallInitRoutines();
        }

        private void BuildImportTable()
        {
            if (PeImage.ImportedFunctions.Count == 0)
            {
                return;
            }

            // Resolve the DLL of any functions imported from an API set

            if (PeImage.ImportedFunctions.Exists(function => function.Dll.StartsWith("api-ms")))
            {
                // Read the entries of the API set

                var apiSetNamespace = MemoryManager.ReadVirtualMemory<ApiSetNamespace>(ProcessManager.Process.SafeHandle, ProcessManager.PebManager.ApiSetMapAddress);

                var apiSetMappings = new Dictionary<string, string>();

                for (var namespaceEntryIndex = 0; namespaceEntryIndex < apiSetNamespace.Count; namespaceEntryIndex ++)
                {
                    // Read the name of the namespace entry

                    var namespaceEntry = MemoryManager.ReadVirtualMemory<ApiSetNamespaceEntry>(ProcessManager.Process.SafeHandle, ProcessManager.PebManager.ApiSetMapAddress + apiSetNamespace.EntryOffset + Marshal.SizeOf<ApiSetNamespaceEntry>() * namespaceEntryIndex);

                    var namespaceEntryNameBytes = MemoryManager.ReadVirtualMemory(ProcessManager.Process.SafeHandle, ProcessManager.PebManager.ApiSetMapAddress + namespaceEntry.NameOffset, namespaceEntry.NameLength);

                    var namespaceEntryName = Encoding.Unicode.GetString(namespaceEntryNameBytes) + ".dll";

                    // Read the name of the value entry that the namespace entry maps to

                    var valueEntry = MemoryManager.ReadVirtualMemory<ApiSetValueEntry>(ProcessManager.Process.SafeHandle, ProcessManager.PebManager.ApiSetMapAddress + namespaceEntry.ValueOffset);

                    var valueEntryNameBytes = MemoryManager.ReadVirtualMemory(ProcessManager.Process.SafeHandle, ProcessManager.PebManager.ApiSetMapAddress + valueEntry.ValueOffset, valueEntry.ValueCount);

                    var valueEntryName = Encoding.Unicode.GetString(valueEntryNameBytes);

                    apiSetMappings.Add(namespaceEntryName, valueEntryName);
                }

                foreach (var function in PeImage.ImportedFunctions.FindAll(f => f.Dll.StartsWith("api-ms")))
                {
                    function.Dll = apiSetMappings[function.Dll];
                }
            }

            // Group the imported functions by the DLL they are imported from

            var groupedFunctions = PeImage.ImportedFunctions.GroupBy(importedFunction => importedFunction.Dll).ToList();

            // Ensure the dependencies of the DLL are loaded in the remote process

            var systemFolderPath = ProcessManager.IsWow64 ? Environment.GetFolderPath(Environment.SpecialFolder.SystemX86) : Environment.GetFolderPath(Environment.SpecialFolder.System);

            foreach (var dll in groupedFunctions)
            {
                var module = ProcessManager.Modules.Find(m => m.Name.Equals(dll.Key, StringComparison.OrdinalIgnoreCase));

                if (module != null)
                {
                    // Increase the reference count of the dependency

                    var ldrAddRefDllAddress = ProcessManager.GetFunctionAddress("ntdll.dll", "LdrAddRefDll");

                    var ntStatus = ProcessManager.CallFunction<int>(CallingConvention.StdCall, ldrAddRefDllAddress, 0, (long) module.BaseAddress);

                    if ((NtStatus) ntStatus != NtStatus.Success)
                    {
                        throw new RemoteFunctionCallException("Failed to call LdrAddRefDll", (NtStatus) ntStatus);
                    }

                    continue;
                }

                // Load the dependency into the remote process

                using (var injector = new Injector(ProcessManager.Process.Id, Path.Combine(systemFolderPath, dll.Key), InjectionMethod.HijackThread))
                {
                    injector.InjectDll();
                }

                ProcessManager.Refresh();
            }

            // Build the import table in the local process

            foreach (var function in groupedFunctions.SelectMany(dll => dll.Select(f => f)))
            {
                var importedFunctionAddress = function.Name is null
                                            ? ProcessManager.GetFunctionAddress(function.Dll, function.Ordinal)
                                            : ProcessManager.GetFunctionAddress(function.Dll, function.Name);

                if (ProcessManager.IsWow64)
                {
                    Marshal.WriteInt32(_localDllAddress + function.Offset, (int) importedFunctionAddress);
                }

                else
                {
                    Marshal.WriteInt64(_localDllAddress + function.Offset, (long) importedFunctionAddress);
                }
            }
        }

        private MemoryProtectionType CalculateSectionProtection(SectionCharacteristics sectionCharacteristics)
        {
            if (sectionCharacteristics.HasFlag(SectionCharacteristics.MemExecute))
            {
                if (sectionCharacteristics.HasFlag(SectionCharacteristics.MemWrite))
                {
                    return MemoryProtectionType.ExecuteReadWrite;
                }

                return sectionCharacteristics.HasFlag(SectionCharacteristics.MemRead) ? MemoryProtectionType.ExecuteRead : MemoryProtectionType.Execute;
            }

            if (sectionCharacteristics.HasFlag(SectionCharacteristics.MemWrite))
            {
                return MemoryProtectionType.ReadWrite;
            }

            return sectionCharacteristics.HasFlag(SectionCharacteristics.MemRead) ? MemoryProtectionType.ReadOnly : MemoryProtectionType.NoAccess;
        }

        private void CallInitRoutines()
        {
            // Call any TLS callbacks with DllProcessAttach

            foreach (var tlsCallback in PeImage.TlsCallbacks)
            {
                if (!ProcessManager.CallFunction<bool>(CallingConvention.StdCall, DllBaseAddress + tlsCallback.Offset, (long) DllBaseAddress, Constants.DllProcessAttach, 0))
                {
                    throw new RemoteFunctionCallException("Failed to call the entry point of a TLS callback with DllProcessAttach");
                }
            }

            // Call the entry point of the DLL with DllProcessAttach

            if (PeImage.PeHeaders.PEHeader.AddressOfEntryPoint == 0)
            {
                return;
            }

            if (!ProcessManager.CallFunction<bool>(CallingConvention.StdCall, DllBaseAddress + PeImage.PeHeaders.PEHeader.AddressOfEntryPoint, (long) DllBaseAddress, Constants.DllProcessAttach, 0))
            {
                throw new RemoteFunctionCallException("Failed to call the entry point of the DLL with DllProcessAttach");
            }
        }

        private void EnableExceptionHandling()
        {
            // Add an entry for the DLL to the LdrpInvertedFunctionTable

            var rtlInsertInvertedFunctionTableAddress = ProcessManager.PdbFile.Value.Symbols["RtlInsertInvertedFunctionTable"];

            ProcessManager.CallFunction(CallingConvention.FastCall, rtlInsertInvertedFunctionTableAddress, (long) DllBaseAddress, PeImage.PeHeaders.PEHeader.SizeOfImage);
        }

        private void MapHeaders()
        {
            var headerBytes = new byte[PeImage.PeHeaders.PEHeader.SizeOfHeaders];

            if (InjectionFlags.HasFlag(InjectionFlags.RandomiseDllHeaders))
            {
                // Generate random PE headers

                new Random().NextBytes(headerBytes);
            }

            else
            {
                // Read the PE headers of the DLL

                Marshal.Copy(_localDllAddress, headerBytes, 0, headerBytes.Length);
            }

            // Write the PE headers into the remote process

            MemoryManager.WriteVirtualMemory(ProcessManager.Process.SafeHandle, DllBaseAddress, headerBytes);

            MemoryManager.ProtectVirtualMemory(ProcessManager.Process.SafeHandle, DllBaseAddress, PeImage.PeHeaders.PEHeader.SizeOfHeaders, MemoryProtectionType.ReadOnly);
        }

        private void MapSections()
        {
            foreach (var section in PeImage.PeHeaders.SectionHeaders.Where(s => s.SizeOfRawData != 0))
            {
                // Get the data of the section

                var sectionDataAddress = _localDllAddress + section.PointerToRawData;

                var sectionData = new byte[section.SizeOfRawData];

                Marshal.Copy(sectionDataAddress, sectionData, 0, section.SizeOfRawData);

                // Write the section into the remote process

                var sectionAddress = DllBaseAddress + section.VirtualAddress;

                MemoryManager.WriteVirtualMemory(ProcessManager.Process.SafeHandle, sectionAddress, sectionData);

                // Apply the correct protection to the section

                MemoryManager.ProtectVirtualMemory(ProcessManager.Process.SafeHandle, sectionAddress, section.SizeOfRawData, CalculateSectionProtection(section.SectionCharacteristics));
            }
        }

        private void RelocateImage()
        {
            if (PeImage.BaseRelocations.Count == 0)
            {
                return;
            }

            // Calculate the preferred base address delta

            var delta = (long) DllBaseAddress - (long) PeImage.PeHeaders.PEHeader.ImageBase;

            if (delta == 0)
            {
                return;
            }

            foreach (var baseRelocationBlock in PeImage.BaseRelocations)
            {
                // Calculate the base address of the relocation block

                var baseRelocationBlockAddress = _localDllAddress + baseRelocationBlock.Offset;

                foreach (var relocation in baseRelocationBlock.Relocations)
                {
                    // Calculate the address of the relocation

                    var relocationAddress = baseRelocationBlockAddress + relocation.Offset;

                    switch (relocation.Type)
                    {
                        case RelocationType.HighLow:
                        {
                            // Perform the relocation

                            var relocationValue = Marshal.ReadInt32(relocationAddress) + (int) delta;

                            Marshal.WriteInt32(relocationAddress, relocationValue);

                            break;
                        }

                        case RelocationType.Dir64:
                        {
                            // Perform the relocation

                            var relocationValue = Marshal.ReadInt64(relocationAddress) + delta;

                            Marshal.WriteInt64(relocationAddress, relocationValue);

                            break;
                        }
                    }
                }
            }
        }
    }
}