using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using Bleak.Native.Enumerations;
using Bleak.Native.PInvoke;
using Bleak.Native.Structures;

namespace Bleak.Injection.Methods
{
    internal sealed class ManualMap : InjectionBase
    {
        private byte[] _dllBuffer;

        internal ManualMap(byte[] dllBytes, Process process, InjectionMethod injectionMethod, InjectionFlags injectionFlags) : base(dllBytes, process, injectionMethod, injectionFlags) { }

        internal ManualMap(string dllPath, Process process, InjectionMethod injectionMethod, InjectionFlags injectionFlags) : base(dllPath, process, injectionMethod, injectionFlags) { }

        internal override void Eject()
        {
            CallInitRoutines(DllReason.DllProcessDetach);

            // Remove the entry for the DLL from the LdrpInvertedFunctionTable

            var rtRemoveInvertedFunctionTableAddress = PdbFile.Value.Symbols.First(symbol => symbol.Key.Contains("RtlRemoveInvertedFunctionTable")).Value;

            ProcessManager.CallFunction(CallingConvention.FastCall, rtRemoveInvertedFunctionTableAddress, (long) DllBaseAddress);

            // Decrease the reference count of the DLL dependencies

            var ldrUnloadDllAddress = ProcessManager.GetFunctionAddress("ntdll.dll", "LdrUnloadDll");

            foreach (var dll in PeImage.ImportedFunctions.GroupBy(importedFunction => importedFunction.DllName))
            {
                var dllAddress = ProcessManager.Modules.Find(module => module.Name.Equals(dll.Key, StringComparison.OrdinalIgnoreCase)).BaseAddress;

                var ntStatus = ProcessManager.CallFunction<int>(CallingConvention.StdCall, ldrUnloadDllAddress, (long) dllAddress);

                if ((NtStatus) ntStatus != NtStatus.Success)
                {
                    throw new Win32Exception($"Failed to call LdrUnloadDll in the context of the remote process with error code {Ntdll.RtlNtStatusToDosError((NtStatus) ntStatus)}");
                }
            }

            // Free the memory allocated for the DLL

            ProcessManager.Memory.FreeBlock(DllBaseAddress);
        }

        internal override void Inject()
        {
            _dllBuffer = DllBytes;

            // Allocate memory for the DLL in the process

            try
            {
                DllBaseAddress = ProcessManager.Memory.AllocateBlock((IntPtr) PeImage.Headers.PEHeader.ImageBase, PeImage.Headers.PEHeader.SizeOfImage, ProtectionType.ReadWrite);
            }

            catch (Win32Exception)
            {
                DllBaseAddress = ProcessManager.Memory.AllocateBlock(IntPtr.Zero, PeImage.Headers.PEHeader.SizeOfImage, ProtectionType.ReadWrite);
            }

            BuildImportTable();

            RelocateImage();

            MapSections();

            MapHeaders();

            SetupExceptionHandling();

            CallInitRoutines(DllReason.DllProcessAttach);

            if (InjectionFlags.HasFlag(InjectionFlags.RandomiseDllHeaders))
            {
                RandomiseDllHeaders();
            }
        }

        private static ProtectionType CalculateSectionProtection(SectionCharacteristics sectionCharacteristics)
        {
            if (sectionCharacteristics.HasFlag(SectionCharacteristics.MemExecute))
            {
                if (sectionCharacteristics.HasFlag(SectionCharacteristics.MemWrite))
                {
                    return ProtectionType.ExecuteReadWrite;
                }

                return sectionCharacteristics.HasFlag(SectionCharacteristics.MemRead) ? ProtectionType.ExecuteRead : ProtectionType.Execute;
            }

            if (sectionCharacteristics.HasFlag(SectionCharacteristics.MemWrite))
            {
                return ProtectionType.ReadWrite;
            }

            return sectionCharacteristics.HasFlag(SectionCharacteristics.MemRead) ? ProtectionType.ReadOnly : ProtectionType.NoAccess;
        }

        private void BuildImportTable()
        {
            if (PeImage.ImportedFunctions.Count == 0)
            {
                return;
            }

            if (PeImage.ImportedFunctions.Exists(function => function.DllName.StartsWith("api-ms")))
            {
                var apiSetMappings = new Dictionary<string, string>();

                // Read the entries of the API set

                var apiSetNamespace = ProcessManager.Memory.Read<ApiSetNamespace>(ProcessManager.Peb.ApiSetMapAddress);

                for (var namespaceEntryIndex = 0; namespaceEntryIndex < apiSetNamespace.Count; namespaceEntryIndex ++)
                {
                    // Read the name of the namespace entry

                    var namespaceEntry = ProcessManager.Memory.Read<ApiSetNamespaceEntry>(ProcessManager.Peb.ApiSetMapAddress + apiSetNamespace.EntryOffset + Unsafe.SizeOf<ApiSetNamespaceEntry>() * namespaceEntryIndex);

                    var namespaceEntryNameBytes = ProcessManager.Memory.ReadBlock(ProcessManager.Peb.ApiSetMapAddress + namespaceEntry.NameOffset, namespaceEntry.NameLength);

                    var namespaceEntryName = Encoding.Unicode.GetString(namespaceEntryNameBytes) + ".dll";

                    // Read the name of the value entry that the namespace entry maps to

                    var valueEntry = ProcessManager.Memory.Read<ApiSetValueEntry>(ProcessManager.Peb.ApiSetMapAddress + namespaceEntry.ValueOffset);

                    if (valueEntry.ValueCount == 0)
                    {
                        apiSetMappings.Add(namespaceEntryName, "");
                    }

                    else
                    {
                        var valueEntryNameBytes = ProcessManager.Memory.ReadBlock(ProcessManager.Peb.ApiSetMapAddress + valueEntry.ValueOffset, valueEntry.ValueCount);

                        var valueEntryName = Encoding.Unicode.GetString(valueEntryNameBytes);

                        apiSetMappings.Add(namespaceEntryName, valueEntryName);
                    }
                }

                // Resolve the DLL of the functions imported from an API set

                foreach (var function in PeImage.ImportedFunctions.FindAll(f => f.DllName.StartsWith("api-ms")))
                {
                    function.DllName = apiSetMappings[function.DllName];
                }
            }

            // Ensure the dependencies of the DLL are loaded in the process

            var systemFolderPath = ProcessManager.IsWow64 ? Environment.GetFolderPath(Environment.SpecialFolder.SystemX86) : Environment.GetFolderPath(Environment.SpecialFolder.System);

            foreach (var dll in PeImage.ImportedFunctions.GroupBy(importedFunction => importedFunction.DllName))
            {
                var dependency = ProcessManager.Modules.Find(module => module.Name.Equals(dll.Key, StringComparison.OrdinalIgnoreCase));

                if (dependency is null)
                {
                    // Load the dependency into the process

                    using var injector = new Injector(ProcessManager.Process.Id, Path.Combine(systemFolderPath, dll.Key), InjectionMethod.HijackThread);

                    injector.InjectDll();

                    ProcessManager.Refresh();
                }

                else
                {
                    // Increase the reference count of the dependency

                    var ldrAddRefDllAddress = ProcessManager.GetFunctionAddress("ntdll.dll", "LdrAddRefDll");

                    var ntStatus = ProcessManager.CallFunction<int>(CallingConvention.StdCall, ldrAddRefDllAddress, 0, (long) dependency.BaseAddress);

                    if ((NtStatus) ntStatus != NtStatus.Success)
                    {
                        throw new Win32Exception($"Failed to call LdrAddRefDll in the context of the remote process with error code {Ntdll.RtlNtStatusToDosError((NtStatus) ntStatus)}");
                    }
                }
            }

            // Build the import table in the local process

            foreach (var function in PeImage.ImportedFunctions.GroupBy(importedFunction => importedFunction.DllName).SelectMany(dll => dll.Select(f => f)))
            {
                var importedFunctionAddress = function.Name is null
                                            ? ProcessManager.GetFunctionAddress(function.DllName, function.Ordinal)
                                            : ProcessManager.GetFunctionAddress(function.DllName, function.Name);

                if (ProcessManager.IsWow64)
                {
                    Unsafe.WriteUnaligned(ref _dllBuffer[function.Offset], (int) importedFunctionAddress);
                }

                else
                {
                    Unsafe.WriteUnaligned(ref _dllBuffer[function.Offset], (long) importedFunctionAddress);
                }
            }
        }

        private void CallInitRoutines(DllReason dllReason)
        {
            // Call any TLS callbacks with dllReason

            if (PeImage.TlsCallbacks.Any(tlsCallback => !ProcessManager.CallFunction<bool>(CallingConvention.StdCall, DllBaseAddress + tlsCallback.Offset, (long) DllBaseAddress, (long) dllReason, 0)))
            {
                throw new Win32Exception($"Failed to call the entry point of a TLS callback with {dllReason.ToString()}");
            }

            // Call the entry point of the DLL with dllReason

            if (PeImage.Headers.PEHeader.AddressOfEntryPoint == 0)
            {
                return;
            }

            if (!ProcessManager.CallFunction<bool>(CallingConvention.StdCall, DllBaseAddress + PeImage.Headers.PEHeader.AddressOfEntryPoint, (long) DllBaseAddress, (long) dllReason, 0))
            {
                throw new Win32Exception($"Failed to call the entry point of the DLL with {dllReason.ToString()}");
            }
        }

        private void MapHeaders()
        {
            var headerBytes = new byte[PeImage.Headers.PEHeader.SizeOfHeaders];

            Unsafe.CopyBlockUnaligned(ref headerBytes[0], ref _dllBuffer[0], (uint) headerBytes.Length);

            // Write the PE headers into the process

            ProcessManager.Memory.WriteBlock(DllBaseAddress, headerBytes);

            ProcessManager.Memory.ProtectBlock(DllBaseAddress, headerBytes.Length, ProtectionType.ReadOnly);
        }

        private void MapSections()
        {
            foreach (var section in PeImage.Headers.SectionHeaders.Where(s => s.SizeOfRawData != 0))
            {
                var sectionData = new byte[section.SizeOfRawData];

                Unsafe.CopyBlockUnaligned(ref sectionData[0], ref _dllBuffer[section.PointerToRawData], (uint) section.SizeOfRawData);

                // Write the section into the process

                var sectionAddress = DllBaseAddress + section.VirtualAddress;

                ProcessManager.Memory.WriteBlock(sectionAddress, sectionData);

                ProcessManager.Memory.ProtectBlock(sectionAddress, section.SizeOfRawData, CalculateSectionProtection(section.SectionCharacteristics));
            }
        }

        private void RelocateImage()
        {
            if (PeImage.BaseRelocations.Count == 0)
            {
                return;
            }

            // Calculate the preferred base address delta

            var delta = (long) DllBaseAddress - (long) PeImage.Headers.PEHeader.ImageBase;

            if (delta == 0)
            {
                return;
            }

            foreach (var baseRelocationBlock in PeImage.BaseRelocations)
            {
                foreach (var relocation in baseRelocationBlock.Relocations)
                {
                    var relocationOffset = baseRelocationBlock.Offset + relocation.Offset;

                    switch (relocation.Type)
                    {
                        case RelocationType.HighLow:
                        {
                            // Perform the relocation

                            var relocationValue = Unsafe.ReadUnaligned<int>(ref _dllBuffer[relocationOffset]) + delta;

                            Unsafe.WriteUnaligned(ref _dllBuffer[relocationOffset], relocationValue);

                            break;
                        }

                        case RelocationType.Dir64:
                        {
                            // Perform the relocation

                            var relocationValue = Unsafe.ReadUnaligned<long>(ref _dllBuffer[relocationOffset]) + delta;

                            Unsafe.WriteUnaligned(ref _dllBuffer[relocationOffset], relocationValue);

                            break;
                        }
                    }
                }
            }
        }

        private void SetupExceptionHandling()
        {
            // Add an entry for the DLL to the LdrpInvertedFunctionTable

            var rtlInsertInvertedFunctionTableAddress = PdbFile.Value.Symbols.First(symbol => symbol.Key.Contains("RtlInsertInvertedFunctionTable")).Value;

            ProcessManager.CallFunction(CallingConvention.FastCall, rtlInsertInvertedFunctionTableAddress, (long) DllBaseAddress, PeImage.Headers.PEHeader.SizeOfImage);
        }
    }
}