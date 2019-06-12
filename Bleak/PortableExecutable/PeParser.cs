using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using Bleak.PortableExecutable.Objects;
using Bleak.Shared;
using static Bleak.Native.Constants;
using static Bleak.Native.Enumerations;
using static Bleak.Native.Structures;

namespace Bleak.PortableExecutable
{
    internal class PeParser
    {
        internal readonly PEHeaders PeHeaders;
        
        internal readonly List<BaseRelocation> BaseRelocations;
        
        internal readonly CodeViewDebugDirectoryData DebugData;
        
        internal readonly List<ExportedFunction> ExportedFunctions;
        
        internal readonly List<ImportedFunction> ImportedFunctions;
        
        internal readonly List<TlsCallback> TlsCallbacks;

        private readonly IntPtr _peBuffer;
        
        internal PeParser(byte[] dllBytes)
        {
            using (var peReader = new PEReader(new MemoryStream(dllBytes)))
            {
                DebugData = peReader.ReadCodeViewDebugDirectoryData(peReader.ReadDebugDirectory()[0]);
                
                PeHeaders = peReader.PEHeaders;
            }
            
            var peBufferHandle = GCHandle.Alloc(dllBytes, GCHandleType.Pinned);

            _peBuffer = peBufferHandle.AddrOfPinnedObject();
            
            BaseRelocations = GetBaseRelocations();
            
            ExportedFunctions = GetExportedFunctions();

            ImportedFunctions = GetImportedFunctions();

            TlsCallbacks = GetTlsCallbacks();
            
            peBufferHandle.Free();
        }

        private ulong ConvertRvaToOffset(ulong rva)
        {
            // Look for the section that holds the offset of the relative virtual address
            
            var sectionHeader = PeHeaders.SectionHeaders.First(section => (ulong) section.VirtualAddress <= rva && (ulong) (section.VirtualAddress + section.VirtualSize) > rva);
            
            return (ulong) sectionHeader.PointerToRawData + (rva - (ulong) sectionHeader.VirtualAddress);
        }

        private List<BaseRelocation> GetBaseRelocations()
        {
            var baseRelocations = new List<BaseRelocation>();
            
            // Calculate the offset of the base relocation table

            var baseRelocationTableRva = PeHeaders.PEHeader.BaseRelocationTableDirectory.RelativeVirtualAddress;
            
            if (baseRelocationTableRva == 0)
            {
                // The PE has no base relocations

                return baseRelocations;
            }
            
            var baseRelocationTableOffset = ConvertRvaToOffset((ulong) baseRelocationTableRva);
            
            var baseRelocationOffset = 0U;

            while (true)
            {
                // Read the base relocation
                
                var baseRelocation = Marshal.PtrToStructure<ImageBaseRelocation>(_peBuffer.AddOffset(baseRelocationTableOffset + baseRelocationOffset));
                
                if (baseRelocation.SizeOfBlock == 0)
                {
                    break;
                }
                
                // Calculate the amount of relocations in the base relocation
                
                var relocationsOffset = baseRelocationTableOffset + (uint) Marshal.SizeOf<ImageBaseRelocation>();
                
                var relocationAmount = (baseRelocation.SizeOfBlock - Marshal.SizeOf<ImageBaseRelocation>()) / sizeof(ushort);
                
                var relocations = new List<Relocation>();

                // Read the relocations
                
                for (var relocationIndex = 0; relocationIndex < relocationAmount; relocationIndex += 1)
                {
                    var relocation = Marshal.PtrToStructure<ushort>(_peBuffer.AddOffset(relocationsOffset + (uint) (sizeof(ushort) * relocationIndex)));
                    
                    // The relocation offset is located in the upper 4 bits of the ushort
                    
                    var relocationOffset = relocation & 0xFFF;
                    
                    // The relocation type is located in the lower 12 bits of the ushort
                    
                    var relocationType = relocation >> 12;
                    
                    relocations.Add(new Relocation((ushort) relocationOffset, (RelocationType) relocationType));
                }
                
                baseRelocations.Add(new BaseRelocation(ConvertRvaToOffset(baseRelocation.VirtualAddress), relocations));
                
                // Calculate the offset of the next base relocation
                
                baseRelocationOffset += baseRelocation.SizeOfBlock;
            }
            
            return baseRelocations;
        }
        
        private List<ExportedFunction> GetExportedFunctions()
        {
            var exportedFunctions = new List<ExportedFunction>();

            // Read the export directory
            
            var exportDirectoryRva = PeHeaders.PEHeader.ExportTableDirectory.RelativeVirtualAddress;
            
            if (exportDirectoryRva == 0)
            {
                // The PE has no exported functions

                return exportedFunctions;
            }
            
            var exportDirectoryOffset = ConvertRvaToOffset((ulong) exportDirectoryRva);

            var exportDirectory = Marshal.PtrToStructure<ImageExportDirectory>(_peBuffer.AddOffset(exportDirectoryOffset));
            
            // Read the exported functions

            var exportedFunctionOffsetsOffset = ConvertRvaToOffset(exportDirectory.AddressOfFunctions);

            for (var exportedFunctionIndex = 0; exportedFunctionIndex < exportDirectory.NumberOfFunctions; exportedFunctionIndex += 1)
            {
                var exportedFunctionOffset = Marshal.PtrToStructure<uint>(_peBuffer.AddOffset(exportedFunctionOffsetsOffset + (uint) (sizeof(uint) * exportedFunctionIndex)));
                
                exportedFunctions.Add(new ExportedFunction(null, exportedFunctionOffset, (ushort) (exportDirectory.Base + exportedFunctionIndex)));
            }
            
            // Associate the names of the exported functions
            
            var exportedFunctionNamesOffset = ConvertRvaToOffset(exportDirectory.AddressOfNames);
            
            var exportedFunctionOrdinalsOffset = ConvertRvaToOffset(exportDirectory.AddressOfNameOrdinals);

            for (var exportedFunctionIndex = 0; exportedFunctionIndex < exportDirectory.NumberOfNames; exportedFunctionIndex += 1)
            {
                // Read the name of the exported function
                
                var exportedFunctionNameRva = Marshal.PtrToStructure<uint>(_peBuffer.AddOffset(exportedFunctionNamesOffset + (uint) (sizeof(uint) * exportedFunctionIndex)));
                
                var exportedFunctionNameOffset = ConvertRvaToOffset(exportedFunctionNameRva);
                
                var exportedFunctionName = Marshal.PtrToStringAnsi(_peBuffer.AddOffset(exportedFunctionNameOffset));
                
                var exportedFunctionOrdinal = exportDirectory.Base + Marshal.PtrToStructure<ushort>(_peBuffer.AddOffset(exportedFunctionOrdinalsOffset + (uint) (sizeof(ushort) * exportedFunctionIndex)));
                
                exportedFunctions.Find(exportedFunction => exportedFunction.Ordinal == exportedFunctionOrdinal).Name = exportedFunctionName;
            }
            
            return exportedFunctions;
        }
        
        private List<ImportedFunction> GetImportedFunctions()
        {
            var importedFunctions = new List<ImportedFunction>();

            // Calculate the offset of the import table
            
            var importTableRva = PeHeaders.PEHeader.ImportTableDirectory.RelativeVirtualAddress;

            if (importTableRva == 0)
            {
                // The PE has no imported functions

                return importedFunctions;
            }
            
            var importTableOffset = ConvertRvaToOffset((ulong) importTableRva);

            for (var importDescriptorIndex = 0;; importDescriptorIndex += 1)
            {
                // Read the name import descriptor
                
                var importDescriptor = Marshal.PtrToStructure<ImageImportDescriptor>(_peBuffer.AddOffset(importTableOffset + (uint) (Marshal.SizeOf<ImageImportDescriptor>() * importDescriptorIndex)));

                if (importDescriptor.FirstThunk == 0)
                {
                    break;
                }
                
                var importDescriptorNameOffset = ConvertRvaToOffset(importDescriptor.Name);
                
                var importDescriptorName = Marshal.PtrToStringAnsi(_peBuffer.AddOffset(importDescriptorNameOffset));
                
                // Read the imported functions associated with the import descriptor
                
                var importDescriptorThunkOffset = importDescriptor.OriginalFirstThunk == 0
                                                ? ConvertRvaToOffset(importDescriptor.FirstThunk)
                                                : ConvertRvaToOffset(importDescriptor.OriginalFirstThunk);

                var importDescriptorFirstThunkOffset = ConvertRvaToOffset(importDescriptor.FirstThunk);

                for (var importedFunctionIndex = 0;; importedFunctionIndex += 1)
                {
                    // Read the thunk of the imported function
                    
                    var importedFunctionThunkOffset = PeHeaders.PEHeader.Magic == PEMagic.PE32
                                                    ? importDescriptorThunkOffset + (uint) (sizeof(uint) * importedFunctionIndex)
                                                    : importDescriptorThunkOffset + (uint) (sizeof(ulong) * importedFunctionIndex);
                    
                    var importedFunctionThunk = Marshal.PtrToStructure<uint>(_peBuffer.AddOffset(importedFunctionThunkOffset));
                    
                    if (importedFunctionThunk == 0)
                    {
                        break;
                    }
                    
                    var importedFunctionFirstThunkOffset = PeHeaders.PEHeader.Magic == PEMagic.PE32
                                                         ? importDescriptorFirstThunkOffset + (uint) (sizeof(uint) * importedFunctionIndex)
                                                         : importDescriptorFirstThunkOffset + (uint) (sizeof(ulong) * importedFunctionIndex);
                    
                    // Determine if the function is imported by its ordinal

                    switch (PeHeaders.PEHeader.Magic)
                    {
                        case PEMagic.PE32 when (importedFunctionThunk & OrdinalFlag32) == OrdinalFlag32:
                        {
                            importedFunctions.Add(new ImportedFunction(importDescriptorName, null, importedFunctionFirstThunkOffset, (ushort) (importedFunctionThunk & 0xFFFF)));

                            break;
                        }

                        case PEMagic.PE32Plus when (importedFunctionThunk & OrdinalFlag64) == OrdinalFlag64:
                        {
                            importedFunctions.Add(new ImportedFunction(importDescriptorName, null, importedFunctionFirstThunkOffset, (ushort) (importedFunctionThunk & 0xFFFF)));

                            break;
                        }

                        default:
                        {
                            // Read the ordinal and name of the imported function
                            
                            var importedFunctionOrdinalOffset = ConvertRvaToOffset(importedFunctionThunk);

                            var importedFunctionOrdinal = Marshal.PtrToStructure<ushort>(_peBuffer.AddOffset(importedFunctionOrdinalOffset));
                            
                            var importedFunctionName = Marshal.PtrToStringAnsi(_peBuffer.AddOffset(importedFunctionOrdinalOffset + sizeof(ushort)));
                            
                            importedFunctions.Add(new ImportedFunction(importDescriptorName, importedFunctionName, importedFunctionFirstThunkOffset, importedFunctionOrdinal));

                            break;
                        }
                    }
                }
            }
            
            return importedFunctions;
        }
        
        private List<TlsCallback> GetTlsCallbacks()
        {
            var tlsCallbacks = new List<TlsCallback>();

            // Calculate the offset the TLS directory
            
            var tlsDirectoryRva = PeHeaders.PEHeader.ThreadLocalStorageTableDirectory.RelativeVirtualAddress;
            
            if (tlsDirectoryRva == 0)
            {
                // The PE has no TLS directory
                
                return tlsCallbacks;
            }
            
            var tlsDirectoryOffset = ConvertRvaToOffset((ulong) tlsDirectoryRva);
            
            // Calculate the offset of the TLS callbacks
            
            ulong tlsCallbacksRva;
            
            if (PeHeaders.PEHeader.Magic == PEMagic.PE32)
            {
                // Read the TLS directory
                
                var tlsDirectory = Marshal.PtrToStructure<ImageTlsDirectory32>(_peBuffer.AddOffset(tlsDirectoryOffset));

                if (tlsDirectory.AddressOfCallbacks == 0)
                {
                    // The PE has no TLS callbacks

                    return tlsCallbacks;
                }

                tlsCallbacksRva = tlsDirectory.AddressOfCallbacks;
            }
            
            else
            {
                // Read the TLS directory
                
                var tlsDirectory = Marshal.PtrToStructure<ImageTlsDirectory64>(_peBuffer.AddOffset(tlsDirectoryOffset));

                if (tlsDirectory.AddressOfCallbacks == 0)
                {
                    // The PE has no TLS callbacks

                    return tlsCallbacks;
                }

                tlsCallbacksRva = tlsDirectory.AddressOfCallbacks;
            }

            var tlsCallbacksOffset = ConvertRvaToOffset(tlsCallbacksRva - PeHeaders.PEHeader.ImageBase);
            
            // Read the offsets of the TLS callbacks

            for (var tlsCallbackIndex = 0;; tlsCallbackIndex += 1)
            {
                var tlsCallbackRva = PeHeaders.PEHeader.Magic == PEMagic.PE32
                                   ? Marshal.PtrToStructure<uint>(_peBuffer.AddOffset(tlsCallbacksOffset + (uint) (sizeof(uint) * tlsCallbackIndex)))
                                   : Marshal.PtrToStructure<ulong>(_peBuffer.AddOffset(tlsCallbacksOffset + (uint) (sizeof(ulong) * tlsCallbackIndex)));
                
                if (tlsCallbackRva == 0)
                {
                    break;
                }
                
                var tlsCallbackOffset = ConvertRvaToOffset(tlsCallbackRva - PeHeaders.PEHeader.ImageBase);
                
                tlsCallbacks.Add(new TlsCallback(tlsCallbackOffset));
            }
            
            return tlsCallbacks;
        }
    }
}