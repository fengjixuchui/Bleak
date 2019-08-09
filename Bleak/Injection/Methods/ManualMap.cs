using System;
using System.IO;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using Bleak.Injection.Interfaces;
using Bleak.Injection.Objects;
using Bleak.Native;
using Bleak.Native.Enumerations;
using Bleak.PortableExecutable;
using Bleak.RemoteProcess;
using Bleak.Shared.Exceptions;

namespace Bleak.Injection.Methods
{
    internal class ManualMap : IInjectionMethod
    {
        private readonly InjectionFlags _injectionFlags;
        
        private readonly IntPtr _localDllAddress;
        
        private readonly PeImage _peImage;

        private readonly ManagedProcess _process;
        
        private IntPtr _remoteDllAddress;
        
        internal ManualMap(InjectionWrapper injectionWrapper)
        {
            _injectionFlags = injectionWrapper.InjectionFlags;
            
            _localDllAddress = Marshal.AllocHGlobal(injectionWrapper.DllBytes.Length);
            
            Marshal.Copy(injectionWrapper.DllBytes, 0, _localDllAddress, injectionWrapper.DllBytes.Length);
            
            _peImage = injectionWrapper.PeImage;
            
            _process = injectionWrapper.Process;
        }
        
        public void Dispose()
        {
            Marshal.FreeHGlobal(_localDllAddress);
            
            _peImage.Dispose();
            
            _process.Dispose();
        }

        public IntPtr Call()
        {
            // Allocate memory for the DLL in the remote process
            
            try
            {
                _remoteDllAddress = _process.MemoryManager.AllocateVirtualMemory((IntPtr) _peImage.PeHeaders.PEHeader.ImageBase, _peImage.PeHeaders.PEHeader.SizeOfImage, MemoryProtectionType.ReadWrite);
            }

            catch (PInvokeException)
            {
                _remoteDllAddress = _process.MemoryManager.AllocateVirtualMemory(_peImage.PeHeaders.PEHeader.SizeOfImage, MemoryProtectionType.ReadWrite);
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

            return _remoteDllAddress;
        }

        private void BuildImportTable()
        {
            if (_peImage.ImportedFunctions.Value.Count == 0)
            {
                return;
            }

            // Group the imported functions by the DLL they are imported from
            
            var groupedFunctions = _peImage.ImportedFunctions.Value.GroupBy(importedFunction => importedFunction.Dll).ToList();

            // Ensure the dependencies of the DLL are loaded in the remote process
            
            var systemFolderPath = _process.IsWow64 ? Environment.GetFolderPath(Environment.SpecialFolder.SystemX86) : Environment.GetFolderPath(Environment.SpecialFolder.System);

            foreach (var dll in groupedFunctions)
            {
                var module = _process.Modules.Find(m => m.Name.Equals(dll.Key, StringComparison.OrdinalIgnoreCase));
                
                if (module != null)
                {
                    // Increase the reference count of the dependency
                    
                    var ldrAddRefDllAddress = _process.GetFunctionAddress("ntdll.dll", "LdrAddRefDll");
                    
                    var ntStatus = _process.CallFunction<int>(CallingConvention.StdCall, ldrAddRefDllAddress, 0, (long) module.BaseAddress);

                    if ((NtStatus) ntStatus != NtStatus.Success)
                    {
                        throw new RemoteFunctionCallException("Failed to call LdrAddRefDll", (NtStatus) ntStatus);
                    }
                    
                    continue;
                }
                
                // Load the dependency into the remote process

                using (var injector = new Injector(_process.Process.Id, Path.Combine(systemFolderPath, dll.Key), InjectionMethod.HijackThread))
                {
                    injector.InjectDll();
                }
                
                _process.Refresh();
            }

            // Build the import table in the local process
            
            foreach (var function in groupedFunctions.SelectMany(dll => dll.Select(f => f)))
            {
                var importedFunctionAddress = function.Name is null
                                            ? _process.GetFunctionAddress(function.Dll, function.Ordinal)
                                            : _process.GetFunctionAddress(function.Dll, function.Name);

                if (_process.IsWow64)
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
            
            foreach (var tlsCallback in _peImage.TlsCallbacks.Value)
            {
                if (!_process.CallFunction<bool>(CallingConvention.StdCall, _remoteDllAddress + tlsCallback.Offset, (long) _remoteDllAddress, Constants.DllProcessAttach, 0))
                {
                    throw new RemoteFunctionCallException("Failed to call the entry point of a TLS callback");
                }
            }
            
            // Call the entry point of the DLL with DllProcessAttach
            
            if (_peImage.PeHeaders.PEHeader.AddressOfEntryPoint == 0)
            {
                return;
            }
            
            if (!_process.CallFunction<bool>(CallingConvention.StdCall, _remoteDllAddress + _peImage.PeHeaders.PEHeader.AddressOfEntryPoint, (long) _remoteDllAddress, Constants.DllProcessAttach, 0))
            {
                throw new RemoteFunctionCallException("Failed to call the entry point of the DLL");
            }
        }

        private void EnableExceptionHandling()
        {
            // Add an entry for the DLL to the LdrpInvertedFunctionTable
            
            var rtlInsertInvertedFunctionTableAddress = _process.PdbFile.Value.GetSymbolAddress(new Regex("RtlInsertInvertedFunctionTable"));
            
            _process.CallFunction(CallingConvention.FastCall, rtlInsertInvertedFunctionTableAddress, (long) _remoteDllAddress, _peImage.PeHeaders.PEHeader.SizeOfImage);
        }

        private void MapHeaders()
        {
            var headerBytes = new byte[_peImage.PeHeaders.PEHeader.SizeOfHeaders];
            
            if (_injectionFlags.HasFlag(InjectionFlags.RandomiseDllHeaders))
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
            
            _process.MemoryManager.WriteVirtualMemory(_remoteDllAddress, headerBytes);

            _process.MemoryManager.ProtectVirtualMemory(_remoteDllAddress, _peImage.PeHeaders.PEHeader.SizeOfHeaders, MemoryProtectionType.ReadOnly);
        }

        private void MapSections()
        {
            foreach (var section in _peImage.PeHeaders.SectionHeaders.Where(s => s.SizeOfRawData != 0))
            {
                // Get the data of the section
                
                var sectionDataAddress = _localDllAddress + section.PointerToRawData;

                var sectionData = new byte[section.SizeOfRawData];
                
                Marshal.Copy(sectionDataAddress, sectionData, 0, section.SizeOfRawData);
                
                // Write the section into the remote process
                
                var sectionAddress = _remoteDllAddress + section.VirtualAddress;

                _process.MemoryManager.WriteVirtualMemory(sectionAddress, sectionData);
                
                // Apply the correct protection to the section
                
                _process.MemoryManager.ProtectVirtualMemory(sectionAddress, section.SizeOfRawData, CalculateSectionProtection(section.SectionCharacteristics));
            }
        }

        private void RelocateImage()
        {
            if (_peImage.BaseRelocations.Value.Count == 0)
            {
                return;
            }
            
            // Calculate the preferred base address delta
            
            var delta = (long) _remoteDllAddress - (long) _peImage.PeHeaders.PEHeader.ImageBase;
            
            if (delta == 0)
            {
                return;
            }

            foreach (var baseRelocationBlock in _peImage.BaseRelocations.Value)
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