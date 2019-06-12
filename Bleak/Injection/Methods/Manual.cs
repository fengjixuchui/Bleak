using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Text;
using Bleak.Injection.Interfaces;
using Bleak.Injection.Objects;
using Bleak.Shared;
using static Bleak.Native.Constants;
using static Bleak.Native.Enumerations;
using static Bleak.Native.Structures;

namespace Bleak.Injection.Methods
{
    internal class Manual : IInjectionMethod
    {
        private readonly InjectionWrapper _injectionWrapper;

        private List<ApiSetMapping> _apiSetMappings;
        
        private IntPtr _localDllAddress;

        private IntPtr _remoteDllAddress;
        
        public Manual(InjectionWrapper injectionWrapper)
        {
            _injectionWrapper = injectionWrapper;
        }
        
        public IntPtr Call()
        {
            var dllBufferHandle = GCHandle.Alloc(_injectionWrapper.DllBytes.Clone(), GCHandleType.Pinned);
            
            _localDllAddress = dllBufferHandle.AddrOfPinnedObject();

            _apiSetMappings = GetApiSetMappings();
            
            // Build the import table of the DLL in the local process
            
            BuildImportTable();
            
            // Allocate memory for the DLL in the remote process

            try
            {
                _remoteDllAddress = _injectionWrapper.MemoryManager.AllocateVirtualMemory((IntPtr) _injectionWrapper.PeParser.PeHeaders.PEHeader.ImageBase, _injectionWrapper.PeParser.PeHeaders.PEHeader.SizeOfImage);
            }

            catch (Win32Exception)
            {
                _remoteDllAddress = _injectionWrapper.MemoryManager.AllocateVirtualMemory(_injectionWrapper.PeParser.PeHeaders.PEHeader.SizeOfImage);
            }
            
            // Relocate the DLL in the local process

            RelocateImage();
            
            // Map the sections of the DLL into the remote process

            MapSections();
            
            // Map the headers of the DLL into the remote process

            MapHeaders();
            
            // Enable exception handling within the DLL
            
            EnableExceptionHandling();
            
            // Call any TLS callbacks

            CallTlsCallbacks();

            // Call the entry point of the DLL
            
            var entryPointAddress = _remoteDllAddress.AddOffset(_injectionWrapper.PeParser.PeHeaders.PEHeader.AddressOfEntryPoint);
            
            if (entryPointAddress != _remoteDllAddress)
            {
                CallEntryPoint(entryPointAddress);
            }
            
            dllBufferHandle.Free();
            
            return _remoteDllAddress;
        }

        private void BuildImportTable()
        {
            if (_injectionWrapper.PeParser.ImportedFunctions.Count == 0)
            {
                // The DLL has no imported functions
                
                return;
            }
            
            // Resolve the DLL of any function imported from a virtual DLL

            foreach (var importedFunction in _injectionWrapper.PeParser.ImportedFunctions)
            {
                if (importedFunction.Dll.StartsWith("api-ms"))
                {
                    importedFunction.Dll = _apiSetMappings.Find(apiSetMapping => apiSetMapping.VirtualDll.Equals(importedFunction.Dll, StringComparison.OrdinalIgnoreCase)).MappedToDll;
                }
            }
            
            // Group the imported functions by the DLL they reside in

            var groupedFunctions = _injectionWrapper.PeParser.ImportedFunctions.GroupBy(importedFunction => importedFunction.Dll).ToList();
            
            // Ensure the dependencies of the DLL are loaded in the remote process
            
            var systemFolderPath = _injectionWrapper.ProcessManager.IsWow64
                                 ? Environment.GetFolderPath(Environment.SpecialFolder.SystemX86)
                                 : Environment.GetFolderPath(Environment.SpecialFolder.System);
            
            foreach (var dll in groupedFunctions)
            {
                if (_injectionWrapper.ProcessManager.Modules.Any(module => module.Name.Equals(dll.Key, StringComparison.OrdinalIgnoreCase)))
                {
                    continue;
                }
                
                // Load the DLL into the remote process

                using (var injector = new Injector(InjectionMethod.CreateThread, _injectionWrapper.ProcessManager.Process.Id, Path.Combine(systemFolderPath, dll.Key)))
                {
                    injector.InjectDll();
                }

                _injectionWrapper.ProcessManager.Refresh();
            }
            
            foreach (var importedFunction in groupedFunctions.SelectMany(dll => dll.Select(importedFunction => importedFunction)))
            {
                // Write the imported function into the local process

                var importedFunctionAddress = importedFunction.Name is null
                                            ? _injectionWrapper.ProcessManager.GetFunctionAddress(importedFunction.Dll, importedFunction.Ordinal)
                                            : _injectionWrapper.ProcessManager.GetFunctionAddress(importedFunction.Dll, importedFunction.Name);

                Marshal.WriteIntPtr(_localDllAddress.AddOffset(importedFunction.Offset), importedFunctionAddress);
            }
        }

        private void CallEntryPoint(IntPtr entryPointAddress)
        {
            if (!_injectionWrapper.ProcessManager.CallFunction<bool>(CallingConvention.StdCall, entryPointAddress, (ulong) _remoteDllAddress, DllProcessAttach, 0))
            {
                throw new Win32Exception("Failed to call the entry point of the DLL or a TLS callback in the remote process");
            }
        }

        private void CallTlsCallbacks()
        {
            foreach (var tlsCallback in _injectionWrapper.PeParser.TlsCallbacks)
            {
                CallEntryPoint(_remoteDllAddress.AddOffset(tlsCallback.Offset));
            }
        }

        private void EnableExceptionHandling()
        {
            if (_injectionWrapper.ProcessManager.IsWow64)
            {
                // Get the address of the RtlInsertInvertedFunctionTable function

                var rtlInsertInvertedFunctionTableAddress = _injectionWrapper.ProcessManager.GetSymbolAddress("_RtlInsertInvertedFunctionTable@8");
                
                // Add an entry for the DLL to the LdrpInvertedFunctionTable

                _injectionWrapper.ProcessManager.CallFunction(CallingConvention.FastCall, rtlInsertInvertedFunctionTableAddress, (ulong) _remoteDllAddress, (ulong) _injectionWrapper.PeParser.PeHeaders.PEHeader.SizeOfImage);
            }

            else
            {
                // Calculate the address of the exception table

                var exceptionTable = _injectionWrapper.PeParser.PeHeaders.PEHeader.ExceptionTableDirectory;
                
                var exceptionTableAddress = _remoteDllAddress.AddOffset(exceptionTable.RelativeVirtualAddress);
                
                // Calculate the amount of entries in the exception table
                
                var exceptionTableAmount = exceptionTable.Size / Marshal.SizeOf<ImageRuntimeFunctionEntry>();
                
                // Add the exception table to the dynamic function table of the remote process

                var rtlAddFunctionTableAddress = _injectionWrapper.ProcessManager.GetFunctionAddress("kernel32.dll", "RtlAddFunctionTable");

                if (!_injectionWrapper.ProcessManager.CallFunction<bool>(CallingConvention.StdCall, rtlAddFunctionTableAddress, (ulong) exceptionTableAddress, (uint) exceptionTableAmount, (ulong) _remoteDllAddress))
                {
                    throw new Win32Exception("Failed to add an exception table to the dynamic function table of the remote process");
                }
            }
        }

        private List<ApiSetMapping> GetApiSetMappings()
        {
            var apiSetMappings = new List<ApiSetMapping>();
            
            // Read the namespace of the API set

            var apiSetDataAddress = _injectionWrapper.ProcessManager.Peb.ApiSetMapAddress;
            
            var apiSetNamespace = _injectionWrapper.MemoryManager.ReadVirtualMemory<ApiSetNamespace>(apiSetDataAddress);
            
            // Read the entries of the API set

            for (var namespaceEntryIndex = 0; namespaceEntryIndex < (int) apiSetNamespace.Count; namespaceEntryIndex += 1)
            {
                // Read the name of the namespace entry
                
                var namespaceEntry = _injectionWrapper.MemoryManager.ReadVirtualMemory<ApiSetNamespaceEntry>(apiSetDataAddress.AddOffset(apiSetNamespace.EntryOffset + Marshal.SizeOf<ApiSetNamespaceEntry>() * namespaceEntryIndex));
                
                var namespaceEntryNameBytes = _injectionWrapper.MemoryManager.ReadVirtualMemory(apiSetDataAddress.AddOffset(namespaceEntry.NameOffset), (int) namespaceEntry.NameLength);

                var namespaceEntryName = Encoding.Unicode.GetString(namespaceEntryNameBytes) + ".dll";
                
                // Read the name of the value entry that the namespace entry maps to
                
                var valueEntry = _injectionWrapper.MemoryManager.ReadVirtualMemory<ApiSetValueEntry>(apiSetDataAddress.AddOffset(namespaceEntry.ValueOffset));
                
                var valueEntryNameBytes = _injectionWrapper.MemoryManager.ReadVirtualMemory(apiSetDataAddress.AddOffset(valueEntry.ValueOffset), (int) valueEntry.ValueCount);
                
                var valueEntryName = Encoding.Unicode.GetString(valueEntryNameBytes);
                
                apiSetMappings.Add(new ApiSetMapping(valueEntryName, namespaceEntryName));
            }
            
            return apiSetMappings;
        }

        private MemoryProtection GetSectionProtection(SectionCharacteristics sectionCharacteristics)
        {
            // Determine the protection of the section

            var sectionProtection = default(MemoryProtection);

            if (sectionCharacteristics.HasFlag(SectionCharacteristics.MemNotCached))
            {
                sectionProtection |= MemoryProtection.NoCache;
            }

            if (sectionCharacteristics.HasFlag(SectionCharacteristics.MemExecute))
            {
                if (sectionCharacteristics.HasFlag(SectionCharacteristics.MemRead))
                {
                    if (sectionCharacteristics.HasFlag(SectionCharacteristics.MemWrite))
                    {
                        sectionProtection |= MemoryProtection.ExecuteReadWrite;
                    }

                    else
                    {
                        sectionProtection |= MemoryProtection.ExecuteRead;
                    }
                }

                else if (sectionCharacteristics.HasFlag(SectionCharacteristics.MemWrite))
                {
                    sectionProtection |= MemoryProtection.ExecuteWriteCopy;
                }

                else
                {
                    sectionProtection |= MemoryProtection.Execute;
                }
            }

            else
            {
                if (sectionCharacteristics.HasFlag(SectionCharacteristics.MemRead))
                {
                    if (sectionCharacteristics.HasFlag(SectionCharacteristics.MemWrite))
                    {
                        sectionProtection |= MemoryProtection.ReadWrite;
                    }

                    else
                    {
                        sectionProtection |= MemoryProtection.ReadOnly;
                    }
                }

                else if (sectionCharacteristics.HasFlag(SectionCharacteristics.MemWrite))
                {
                    sectionProtection |= MemoryProtection.WriteCopy;
                }

                else
                {
                    sectionProtection |= MemoryProtection.NoAccess;
                }
            }

            return sectionProtection;
        }

        private void MapHeaders()
        {
            // Read the PE headers of the DLL
            
            var headerBytes = new byte[_injectionWrapper.PeParser.PeHeaders.PEHeader.SizeOfHeaders];
            
            Marshal.Copy(_localDllAddress, headerBytes, 0, headerBytes.Length);
            
            // Write the PE headers into the remote process

            _injectionWrapper.MemoryManager.WriteVirtualMemory(_remoteDllAddress, headerBytes);

            _injectionWrapper.MemoryManager.ProtectVirtualMemory(_remoteDllAddress, _injectionWrapper.PeParser.PeHeaders.PEHeader.SizeOfHeaders, MemoryProtection.ReadOnly);
        }

        private void MapSections()
        {
            foreach (var section in _injectionWrapper.PeParser.PeHeaders.SectionHeaders)
            {
                if (section.SizeOfRawData == 0)
                {
                    continue;
                }
                
                // Get the data of the section

                var sectionDataAddress = _localDllAddress.AddOffset(section.PointerToRawData);

                var sectionData = new byte[section.SizeOfRawData];
                
                Marshal.Copy(sectionDataAddress, sectionData, 0, section.SizeOfRawData);
                
                // Write the section into the remote process

                var sectionAddress = _remoteDllAddress.AddOffset(section.VirtualAddress);

                _injectionWrapper.MemoryManager.WriteVirtualMemory(sectionAddress, sectionData);
                
                // Adjust the protection of the section

                var sectionProtection = GetSectionProtection(section.SectionCharacteristics);

                _injectionWrapper.MemoryManager.ProtectVirtualMemory(sectionAddress, section.SizeOfRawData, sectionProtection);
            }
        }

        private void RelocateImage()
        {
            if (_injectionWrapper.PeParser.BaseRelocations.Count == 0)
            {
                // No relocations need to be applied
                
                return;
            }
            
            // Calculate the preferred base address delta

            var delta = (long) _remoteDllAddress - (long) _injectionWrapper.PeParser.PeHeaders.PEHeader.ImageBase;

            if (delta == 0)
            {
                // The DLL is loaded at its preferred base address then no relocations need to be applied
                
                return;
            }

            foreach (var baseRelocation in _injectionWrapper.PeParser.BaseRelocations)
            {
                // Calculate the base address of the relocation block
                
                var relocationBlockAddress = _localDllAddress.AddOffset(baseRelocation.Offset);

                foreach (var relocation in baseRelocation.Relocations)
                {
                    // Calculate the address of the relocation

                    var relocationAddress = relocationBlockAddress.AddOffset(relocation.Offset);

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