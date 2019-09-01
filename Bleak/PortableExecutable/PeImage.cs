using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using Bleak.Native;
using Bleak.Native.Enumerations;
using Bleak.Native.Structures;

namespace Bleak.PortableExecutable
{
    internal class PeImage
    {
        internal readonly PEHeaders PeHeaders;

        internal readonly List<BaseRelocation> BaseRelocations;

        internal readonly List<ExportedFunction> ExportedFunctions;

        internal readonly List<ImportedFunction> ImportedFunctions;

        internal readonly PdbDebugData PdbDebugData;

        internal readonly List<TlsCallback> TlsCallbacks;

        internal PeImage(byte[] peBytes)
        {
            using (var peReader = new PEReader(new MemoryStream(peBytes)))
            {
                PeHeaders = peReader.PEHeaders;
            }

            ValidatePe();

            var peBuffer = Marshal.AllocHGlobal(peBytes.Length);

            Marshal.Copy(peBytes, 0, peBuffer, peBytes.Length);

            BaseRelocations = ParseBaseRelocations(peBuffer);

            ExportedFunctions = ParseExportedFunctions(peBuffer);

            ImportedFunctions = ParseImportedFunctions(peBuffer);

            PdbDebugData = ParsePdbData(peBuffer);

            TlsCallbacks = ParseTlsCallbacks(peBuffer);

            Marshal.FreeHGlobal(peBuffer);
        }

        private List<BaseRelocation> ParseBaseRelocations(IntPtr peBuffer)
        {
            var baseRelocations = new List<BaseRelocation>();

            // Calculate the offset of the base relocation table

            if (PeHeaders.PEHeader.BaseRelocationTableDirectory.RelativeVirtualAddress == 0)
            {
                return baseRelocations;
            }

            var baseRelocationTableOffset = RvaToVa(PeHeaders.PEHeader.BaseRelocationTableDirectory.RelativeVirtualAddress);

            // Read the base relocation blocks from the base relocation table

            var currentBaseRelocationBlockOffset = baseRelocationTableOffset;

            while (true)
            {
                var baseRelocationBlock = Marshal.PtrToStructure<ImageBaseRelocation>(peBuffer + currentBaseRelocationBlockOffset);

                if (baseRelocationBlock.SizeOfBlock == 0)
                {
                    break;
                }

                // Read the relocations from the base relocation block

                var relocationAmount = (baseRelocationBlock.SizeOfBlock - Marshal.SizeOf<ImageBaseRelocation>()) / sizeof(short);

                var relocations = new List<Relocation>();

                for (var relocationIndex = 0; relocationIndex < relocationAmount; relocationIndex ++)
                {
                    var relocation = Marshal.PtrToStructure<ushort>(peBuffer + currentBaseRelocationBlockOffset + Marshal.SizeOf<ImageBaseRelocation>() + sizeof(short) * relocationIndex);

                    var relocationOffset = relocation & 0xFFF;

                    var relocationType = relocation >> 12;

                    relocations.Add(new Relocation((short) relocationOffset, (RelocationType) relocationType));
                }

                baseRelocations.Add(new BaseRelocation(RvaToVa(baseRelocationBlock.VirtualAddress), relocations));

                // Calculate the offset of the next base relocation block

                currentBaseRelocationBlockOffset += baseRelocationBlock.SizeOfBlock;
            }

            return baseRelocations;
        }

        private List<ExportedFunction> ParseExportedFunctions(IntPtr peBuffer)
        {
            var exportedFunctions = new List<ExportedFunction>();

            // Read the export table

            if (PeHeaders.PEHeader.ExportTableDirectory.RelativeVirtualAddress == 0)
            {
                return exportedFunctions;
            }

            var exportTable = Marshal.PtrToStructure<ImageExportDirectory>(peBuffer + RvaToVa(PeHeaders.PEHeader.ExportTableDirectory.RelativeVirtualAddress));

            // Read the exported functions from the export table

            var exportedFunctionOffsets = new int[exportTable.NumberOfFunctions];

            Marshal.Copy(peBuffer + RvaToVa(exportTable.AddressOfFunctions), exportedFunctionOffsets, 0, exportTable.NumberOfFunctions);

            for (var exportedFunctionIndex = 0; exportedFunctionIndex < exportTable.NumberOfFunctions; exportedFunctionIndex ++)
            {
                exportedFunctions.Add(new ExportedFunction(null, exportedFunctionOffsets[exportedFunctionIndex], (short) (exportTable.Base + exportedFunctionIndex)));
            }

            // Associate names with the exported functions

            var exportedFunctionNameRvas = new int[exportTable.NumberOfNames];

            Marshal.Copy(peBuffer + RvaToVa(exportTable.AddressOfNames), exportedFunctionNameRvas, 0, exportTable.NumberOfNames);

            var exportedFunctionOrdinals = new short[exportTable.NumberOfNames];

            Marshal.Copy(peBuffer + RvaToVa(exportTable.AddressOfNameOrdinals), exportedFunctionOrdinals, 0, exportTable.NumberOfNames);

            for (var exportedFunctionIndex = 0; exportedFunctionIndex < exportTable.NumberOfNames; exportedFunctionIndex ++)
            {
                // Read the name of the exported function

                var exportedFunctionName = Marshal.PtrToStringAnsi(peBuffer + RvaToVa(exportedFunctionNameRvas[exportedFunctionIndex]));

                var exportedFunctionOrdinal = exportTable.Base + exportedFunctionOrdinals[exportedFunctionIndex];

                exportedFunctions.Find(exportedFunction => exportedFunction.Ordinal == exportedFunctionOrdinal).Name = exportedFunctionName;
            }

            return exportedFunctions;
        }

        private List<ImportedFunction> ParseImportedFunctions(IntPtr peBuffer)
        {
            var importedFunctions = new List<ImportedFunction>();

            void ReadImportedFunctions(string descriptorName, int descriptorThunkOffset, int importAddressTableOffset)
            {
                for (var importedFunctionIndex = 0;; importedFunctionIndex++)
                {
                    // Read the thunk of the imported function

                    var importedFunctionThunkOffset = PeHeaders.PEHeader.Magic == PEMagic.PE32
                                                    ? descriptorThunkOffset + sizeof(int) * importedFunctionIndex
                                                    : descriptorThunkOffset + sizeof(long) * importedFunctionIndex;

                    var importedFunctionThunk = Marshal.ReadInt32(peBuffer + importedFunctionThunkOffset);

                    if (importedFunctionThunk == 0)
                    {
                        break;
                    }

                    // Determine if the function is imported by its ordinal

                    var importAddressTableFunctionOffset = PeHeaders.PEHeader.Magic == PEMagic.PE32
                                                         ? importAddressTableOffset + sizeof(int) * importedFunctionIndex
                                                         : importAddressTableOffset + sizeof(long) * importedFunctionIndex;

                    switch (PeHeaders.PEHeader.Magic)
                    {
                        case PEMagic.PE32 when (importedFunctionThunk & Constants.OrdinalFlag32) == Constants.OrdinalFlag32:
                        {
                            importedFunctions.Add(new ImportedFunction(descriptorName, null, importAddressTableFunctionOffset, (short) (importedFunctionThunk & 0xFFFF)));

                            break;
                        }

                        case PEMagic.PE32Plus when ((ulong) importedFunctionThunk & Constants.OrdinalFlag64) == Constants.OrdinalFlag64:
                        {
                            importedFunctions.Add(new ImportedFunction(descriptorName, null, importAddressTableFunctionOffset, (short) (importedFunctionThunk & 0xFFFF)));

                            break;
                        }

                        default:
                        {
                            // Read the ordinal of the imported function

                            var importedFunctionOrdinalOffset = RvaToVa(importedFunctionThunk);

                            var importedFunctionOrdinal = Marshal.ReadInt16(peBuffer + importedFunctionOrdinalOffset);

                            // Read the name of the imported function

                            var importedFunctionName = Marshal.PtrToStringAnsi(peBuffer + importedFunctionOrdinalOffset + sizeof(short));

                            importedFunctions.Add(new ImportedFunction(descriptorName, importedFunctionName, importAddressTableFunctionOffset, importedFunctionOrdinal));

                            break;
                        }
                    }
                }
            }

            // Calculate the offset of the import table

            if (PeHeaders.PEHeader.ImportTableDirectory.RelativeVirtualAddress == 0)
            {
                return importedFunctions;
            }

            var importTableOffset = RvaToVa(PeHeaders.PEHeader.ImportTableDirectory.RelativeVirtualAddress);

            for (var importDescriptorIndex = 0;; importDescriptorIndex ++)
            {
                // Read the name of the import descriptor

                var importDescriptor = Marshal.PtrToStructure<ImageImportDescriptor>(peBuffer + importTableOffset + Marshal.SizeOf<ImageImportDescriptor>() * importDescriptorIndex);

                if (importDescriptor.Name == 0)
                {
                    break;
                }

                var importDescriptorName = Marshal.PtrToStringAnsi(peBuffer + RvaToVa(importDescriptor.Name));

                // Read the functions imported from the import descriptor

                var importDescriptorThunkOffset = importDescriptor.OriginalFirstThunk == 0
                                                ? RvaToVa(importDescriptor.FirstThunk)
                                                : RvaToVa(importDescriptor.OriginalFirstThunk);

                var importAddressTableOffset = RvaToVa(importDescriptor.FirstThunk);

                ReadImportedFunctions(importDescriptorName, importDescriptorThunkOffset, importAddressTableOffset);
            }

            // Calculate the offset of the delay load import table

            if (PeHeaders.PEHeader.DelayImportTableDirectory.RelativeVirtualAddress == 0)
            {
                return importedFunctions;
            }

            var delayLoadImportTableOffset = RvaToVa(PeHeaders.PEHeader.DelayImportTableDirectory.RelativeVirtualAddress);

            for (var delayLoadImportDescriptorIndex = 0;; delayLoadImportDescriptorIndex ++)
            {
                // Read the name of the import descriptor

                var importDescriptor = Marshal.PtrToStructure<ImageDelayLoadDescriptor>(peBuffer + delayLoadImportTableOffset + Marshal.SizeOf<ImageDelayLoadDescriptor>() * delayLoadImportDescriptorIndex);

                if (importDescriptor.DllNameRva == 0)
                {
                    break;
                }

                var importDescriptorName = Marshal.PtrToStringAnsi(peBuffer + RvaToVa(importDescriptor.DllNameRva));

                // Read the functions imported from the import descriptor

                var importDescriptorThunkOffset = RvaToVa(importDescriptor.ImportNameTableRva);

                var importAddressTableOffset = RvaToVa(importDescriptor.ImportAddressTableRva);

                ReadImportedFunctions(importDescriptorName, importDescriptorThunkOffset, importAddressTableOffset);
            }

            return importedFunctions;
        }

        private PdbDebugData ParsePdbData(IntPtr peBuffer)
        {
            // Calculate the offset of the debug table

            if (PeHeaders.PEHeader.DebugTableDirectory.RelativeVirtualAddress == 0)
            {
                return default;
            }

            var debugTableOffset = RvaToVa(PeHeaders.PEHeader.DebugTableDirectory.RelativeVirtualAddress);

            // Read the debug table

            var debugTable = Marshal.PtrToStructure<ImageDebugDirectory>(peBuffer + debugTableOffset);

            // Read the name of the PDB associated with the DLL

            var debugDataOffset = RvaToVa(debugTable.AddressOfRawData);

            var debugData = Marshal.PtrToStructure<ImageDebugData>(peBuffer + debugDataOffset);

            var pdbName = Marshal.PtrToStringAnsi(peBuffer + debugDataOffset + Marshal.SizeOf<ImageDebugData>());

            return new PdbDebugData(debugData.Age, debugData.Guid.ToString().Replace("-", ""), pdbName);
        }

        private List<TlsCallback> ParseTlsCallbacks(IntPtr peBuffer)
        {
            var tlsCallbacks = new List<TlsCallback>();

            // Calculate the offset of the TLS table

            if (PeHeaders.PEHeader.ThreadLocalStorageTableDirectory.RelativeVirtualAddress == 0)
            {
                return tlsCallbacks;
            }

            var tlsTableOffset = RvaToVa(PeHeaders.PEHeader.ThreadLocalStorageTableDirectory.RelativeVirtualAddress);

            // Calculate the offset of the TLS callbacks

            long tlsCallbacksRva;

            if (PeHeaders.PEHeader.Magic == PEMagic.PE32)
            {
                // Read the TLS table

                var tlsTable = Marshal.PtrToStructure<ImageTlsDirectory32>(peBuffer + tlsTableOffset);

                if (tlsTable.AddressOfCallbacks == 0)
                {
                    return tlsCallbacks;
                }

                tlsCallbacksRva = tlsTable.AddressOfCallbacks;
            }

            else
            {
                // Read the TLS table

                var tlsTable = Marshal.PtrToStructure<ImageTlsDirectory64>(peBuffer + tlsTableOffset);

                if (tlsTable.AddressOfCallbacks == 0)
                {
                    return tlsCallbacks;
                }

                tlsCallbacksRva = tlsTable.AddressOfCallbacks;
            }

            var tlsCallbacksOffset = RvaToVa((int) (tlsCallbacksRva - (long) PeHeaders.PEHeader.ImageBase));

            // Read the offsets of the TLS callbacks

            for (var tlsCallbackIndex = 0;; tlsCallbackIndex ++)
            {
                var tlsCallbackRva = PeHeaders.PEHeader.Magic == PEMagic.PE32
                                   ? Marshal.ReadInt32(peBuffer + tlsCallbacksOffset + sizeof(int) * tlsCallbackIndex)
                                   : Marshal.ReadInt64(peBuffer + tlsCallbacksOffset + sizeof(long) * tlsCallbackIndex);

                if (tlsCallbackRva == 0)
                {
                    break;
                }

                tlsCallbacks.Add(new TlsCallback(RvaToVa((int) (tlsCallbacksRva - (long) PeHeaders.PEHeader.ImageBase))));
            }

            return tlsCallbacks;
        }

        private int RvaToVa(int rva)
        {
            var sectionHeader = PeHeaders.SectionHeaders.First(section => section.VirtualAddress <= rva && section.VirtualAddress + section.VirtualSize > rva);

            return sectionHeader.PointerToRawData + (rva - sectionHeader.VirtualAddress);
        }

        private void ValidatePe()
        {
            if (!PeHeaders.IsDll)
            {
                throw new BadImageFormatException("The file provided was not a DLL");
            }

            if (PeHeaders.CorHeader != null)
            {
                throw new BadImageFormatException(".Net DLL's are not supported");
            }
        }
    }
}