using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Runtime.CompilerServices;
using System.Text;
using Bleak.Native;
using Bleak.Native.Enumerations;
using Bleak.Native.Structures;
using Bleak.PortableExecutable.Structures;

namespace Bleak.PortableExecutable
{
    internal sealed class PeImage
    {
        internal readonly List<BaseRelocation> BaseRelocations;

        internal readonly DebugData DebugData;

        internal readonly List<ExportedFunction> ExportedFunctions;

        internal readonly PEHeaders Headers;

        internal readonly List<ImportedFunction> ImportedFunctions;

        internal readonly List<TlsCallback> TlsCallbacks;

        private readonly byte[] _peBytes;

        internal PeImage(byte[] peBytes)
        {
            _peBytes = peBytes;

            Headers = ParseHeaders();

            BaseRelocations = ParseBaseRelocations();

            DebugData = ParseDebugData();

            ExportedFunctions = ParseExportedFunctions();

            ImportedFunctions = ParseImportedFunctions();

            TlsCallbacks = ParseTlsCallbacks();
        }

        private List<BaseRelocation> ParseBaseRelocations()
        {
            var baseRelocations = new List<BaseRelocation>();

            // Calculate the offset of the base relocation table

            if (Headers.PEHeader.BaseRelocationTableDirectory.RelativeVirtualAddress == 0)
            {
                return baseRelocations;
            }

            var baseRelocationTableOffset = RvaToVa(Headers.PEHeader.BaseRelocationTableDirectory.RelativeVirtualAddress);

            // Read the base relocation blocks from the base relocation table

            var currentBaseRelocationBlockOffset = baseRelocationTableOffset;

            while (true)
            {
                var baseRelocationBlock = Unsafe.ReadUnaligned<ImageBaseRelocation>(ref _peBytes[currentBaseRelocationBlockOffset]);

                if (baseRelocationBlock.SizeOfBlock == 0)
                {
                    break;
                }

                // Read the relocations from the base relocation block

                var relocationAmount = (baseRelocationBlock.SizeOfBlock - Unsafe.SizeOf<ImageBaseRelocation>()) / sizeof(short);

                var relocations = new List<Relocation>();

                for (var relocationIndex = 0; relocationIndex < relocationAmount; relocationIndex ++)
                {
                    var relocation = Unsafe.ReadUnaligned<ushort>(ref _peBytes[currentBaseRelocationBlockOffset + Unsafe.SizeOf<ImageBaseRelocation>() + sizeof(short) * relocationIndex]);

                    // The relocation offset is located in the upper 4 bits of the relocation

                    var relocationOffset = relocation & 0xFFF;

                    // The relocation type is located in the lower 12 bits of the relocation

                    var relocationType = relocation >> 12;

                    relocations.Add(new Relocation((short) relocationOffset, (RelocationType) relocationType));
                }

                baseRelocations.Add(new BaseRelocation(RvaToVa(baseRelocationBlock.VirtualAddress), relocations));

                // Calculate the offset of the next base relocation block

                currentBaseRelocationBlockOffset += baseRelocationBlock.SizeOfBlock;
            }

            return baseRelocations;
        }

        private DebugData ParseDebugData()
        {
            // Calculate the offset of the debug table

            if (Headers.PEHeader.DebugTableDirectory.RelativeVirtualAddress == 0)
            {
                return default;
            }

            var debugTableOffset = RvaToVa(Headers.PEHeader.DebugTableDirectory.RelativeVirtualAddress);

            // Read the debug table

            var debugTable = Unsafe.ReadUnaligned<ImageDebugDirectory>(ref _peBytes[debugTableOffset]);

            // Read the name of the PDB associated with the DLL

            var debugDataOffset = RvaToVa(debugTable.AddressOfRawData);

            var debugData = Unsafe.ReadUnaligned<ImageDebugData>(ref _peBytes[debugDataOffset]);

            var pdbNameLength = 0;

            while (_peBytes[debugDataOffset + Unsafe.SizeOf<ImageDebugData>() + pdbNameLength] != 0x00)
            {
                pdbNameLength += 1;
            }

            var pdbName = Encoding.ASCII.GetString(new ReadOnlySpan<byte>(_peBytes).Slice(debugDataOffset + Unsafe.SizeOf<ImageDebugData>(), pdbNameLength));

            return new DebugData(debugData.Age, debugData.Guid.ToString().Replace("-", ""), pdbName);
        }

        private List<ExportedFunction> ParseExportedFunctions()
        {
            var exportedFunctions = new List<ExportedFunction>();

            // Read the export table

            if (Headers.PEHeader.ExportTableDirectory.RelativeVirtualAddress == 0)
            {
                return exportedFunctions;
            }

            var exportTable = Unsafe.ReadUnaligned<ImageExportDirectory>(ref _peBytes[RvaToVa(Headers.PEHeader.ExportTableDirectory.RelativeVirtualAddress)]);

            // Read the exported functions from the export table

            var exportedFunctionOffsetsOffset = RvaToVa(exportTable.AddressOfFunctions);

            for (var exportedFunctionIndex = 0; exportedFunctionIndex < exportTable.NumberOfFunctions; exportedFunctionIndex ++)
            {
                var exportedFunctionOffset = Unsafe.ReadUnaligned<int>(ref _peBytes[exportedFunctionOffsetsOffset + sizeof(int) * exportedFunctionIndex]);

                exportedFunctions.Add(new ExportedFunction(null, exportedFunctionOffset, (short) (exportTable.Base + exportedFunctionIndex)));
            }

            // Associate names with the exported functions

            var exportedFunctionNamesOffset = RvaToVa(exportTable.AddressOfNames);

            var exportedFunctionOrdinalsOffset = RvaToVa(exportTable.AddressOfNameOrdinals);

            for (var exportedFunctionIndex = 0; exportedFunctionIndex < exportTable.NumberOfNames; exportedFunctionIndex ++)
            {
                // Read the name of the exported function

                var exportedFunctionNameOffset = RvaToVa(Unsafe.ReadUnaligned<int>(ref _peBytes[exportedFunctionNamesOffset + sizeof(int) * exportedFunctionIndex]));

                var exportedFunctionNameLength = 0;

                while (_peBytes[exportedFunctionNameOffset + exportedFunctionNameLength] != 0x00)
                {
                    exportedFunctionNameLength += 1;
                }

                var exportedFunctionName = Encoding.ASCII.GetString(new ReadOnlySpan<byte>(_peBytes).Slice(exportedFunctionNameOffset, exportedFunctionNameLength));

                // Read the ordinal of the exported function

                var exportedFunctionOrdinal = exportTable.Base + Unsafe.ReadUnaligned<short>(ref _peBytes[exportedFunctionOrdinalsOffset + sizeof(short) * exportedFunctionIndex]);

                exportedFunctions.Find(exportedFunction => exportedFunction.Ordinal == exportedFunctionOrdinal).Name = exportedFunctionName;
            }

            return exportedFunctions;
        }

        private PEHeaders ParseHeaders()
        {
            using var peReader = new PEReader(new MemoryStream(_peBytes));

            if (!peReader.PEHeaders.IsDll)
            {
                throw new BadImageFormatException("The provided file was not a valid DLL");
            }

            if (peReader.PEHeaders.CorHeader != null)
            {
                throw new BadImageFormatException(".Net DLL's are not supported");
            }

            return peReader.PEHeaders;
        }

        private List<ImportedFunction> ParseImportedFunctions()
        {
            var importedFunctions = new List<ImportedFunction>();

            void ReadImportedFunctions(string descriptorName, int descriptorThunkOffset, int importAddressTableOffset)
            {
                for (var importedFunctionIndex = 0;; importedFunctionIndex ++)
                {
                    // Read the thunk of the imported function

                    var importedFunctionThunkOffset = Headers.PEHeader.Magic == PEMagic.PE32
                                                    ? descriptorThunkOffset + sizeof(int) * importedFunctionIndex
                                                    : descriptorThunkOffset + sizeof(long) * importedFunctionIndex;

                    var importedFunctionThunk = Unsafe.ReadUnaligned<int>(ref _peBytes[importedFunctionThunkOffset]);

                    if (importedFunctionThunk == 0)
                    {
                        break;
                    }

                    // Determine if the function is imported by its ordinal

                    var importAddressTableFunctionOffset = Headers.PEHeader.Magic == PEMagic.PE32
                                                         ? importAddressTableOffset + sizeof(int) * importedFunctionIndex
                                                         : importAddressTableOffset + sizeof(long) * importedFunctionIndex;

                    switch (Headers.PEHeader.Magic)
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

                            var importedFunctionOrdinal = Unsafe.ReadUnaligned<short>(ref _peBytes[importedFunctionOrdinalOffset]);

                            // Read the name of the imported function

                            var importedFunctionNameLength = 0;

                            while (_peBytes[importedFunctionOrdinalOffset + sizeof(short) + importedFunctionNameLength] != 0x00)
                            {
                                importedFunctionNameLength += 1;
                            }

                            var importedFunctionName = Encoding.ASCII.GetString(new ReadOnlySpan<byte>(_peBytes).Slice(importedFunctionOrdinalOffset + sizeof(short), importedFunctionNameLength));

                            importedFunctions.Add(new ImportedFunction(descriptorName, importedFunctionName, importAddressTableFunctionOffset, importedFunctionOrdinal));

                            break;
                        }
                    }
                }
            }

            // Calculate the offset of the import table

            if (Headers.PEHeader.ImportTableDirectory.RelativeVirtualAddress == 0)
            {
                return importedFunctions;
            }

            var importTableOffset = RvaToVa(Headers.PEHeader.ImportTableDirectory.RelativeVirtualAddress);

            for (var importDescriptorIndex = 0;; importDescriptorIndex ++)
            {
                // Read the name of the import descriptor

                var importDescriptor = Unsafe.ReadUnaligned<ImageImportDescriptor>(ref _peBytes[importTableOffset + Unsafe.SizeOf<ImageImportDescriptor>() * importDescriptorIndex]);

                if (importDescriptor.Name == 0)
                {
                    break;
                }

                var importDescriptorNameOffset = RvaToVa(importDescriptor.Name);

                var importDescriptorNameLength = 0;

                while (_peBytes[importDescriptorNameOffset + importDescriptorNameLength] != 0x00)
                {
                    importDescriptorNameLength += 1;
                }

                var importDescriptorName = Encoding.ASCII.GetString(new ReadOnlySpan<byte>(_peBytes).Slice(importDescriptorNameOffset, importDescriptorNameLength));

                // Read the functions imported from the import descriptor

                var importDescriptorThunkOffset = importDescriptor.OriginalFirstThunk == 0
                                                ? RvaToVa(importDescriptor.FirstThunk)
                                                : RvaToVa(importDescriptor.OriginalFirstThunk);

                var importAddressTableOffset = RvaToVa(importDescriptor.FirstThunk);

                ReadImportedFunctions(importDescriptorName, importDescriptorThunkOffset, importAddressTableOffset);
            }

            // Calculate the offset of the delay load import table

            if (Headers.PEHeader.DelayImportTableDirectory.RelativeVirtualAddress == 0)
            {
                return importedFunctions;
            }

            var delayLoadImportTableOffset = RvaToVa(Headers.PEHeader.DelayImportTableDirectory.RelativeVirtualAddress);

            for (var delayLoadImportDescriptorIndex = 0;; delayLoadImportDescriptorIndex ++)
            {
                // Read the name of the import descriptor

                var importDescriptor = Unsafe.ReadUnaligned<ImageDelayLoadDescriptor>(ref _peBytes[delayLoadImportTableOffset + Unsafe.SizeOf<ImageDelayLoadDescriptor>() * delayLoadImportDescriptorIndex]);

                if (importDescriptor.DllNameRva == 0)
                {
                    break;
                }

                var importDescriptorNameOffset = RvaToVa(importDescriptor.DllNameRva);

                var importDescriptorNameLength = 0;

                while (_peBytes[importDescriptorNameOffset + importDescriptorNameLength] != 0x00)
                {
                    importDescriptorNameLength += 1;
                }

                var importDescriptorName = Encoding.ASCII.GetString(new ReadOnlySpan<byte>(_peBytes).Slice(importDescriptorNameOffset, importDescriptorNameLength));

                // Read the functions imported from the import descriptor

                var importDescriptorThunkOffset = RvaToVa(importDescriptor.ImportNameTableRva);

                var importAddressTableOffset = RvaToVa(importDescriptor.ImportAddressTableRva);

                ReadImportedFunctions(importDescriptorName, importDescriptorThunkOffset, importAddressTableOffset);
            }

            return importedFunctions;
        }

        private List<TlsCallback> ParseTlsCallbacks()
        {
            var tlsCallbacks = new List<TlsCallback>();

            // Calculate the offset of the TLS table

            if (Headers.PEHeader.ThreadLocalStorageTableDirectory.RelativeVirtualAddress == 0)
            {
                return tlsCallbacks;
            }

            var tlsTableOffset = RvaToVa(Headers.PEHeader.ThreadLocalStorageTableDirectory.RelativeVirtualAddress);

            // Calculate the offset of the TLS callbacks

            int tlsCallbacksOffset;

            if (Headers.PEHeader.Magic == PEMagic.PE32)
            {
                // Read the TLS table

                var tlsTable = Unsafe.ReadUnaligned<ImageTlsDirectory<int>>(ref _peBytes[tlsTableOffset]);

                if (tlsTable.AddressOfCallbacks == 0)
                {
                    return tlsCallbacks;
                }

                tlsCallbacksOffset = RvaToVa((int) (tlsTable.AddressOfCallbacks - (long) Headers.PEHeader.ImageBase));
            }

            else
            {
                // Read the TLS table

                var tlsTable = Unsafe.ReadUnaligned<ImageTlsDirectory<long>>(ref _peBytes[tlsTableOffset]);

                if (tlsTable.AddressOfCallbacks == 0)
                {
                    return tlsCallbacks;
                }

                tlsCallbacksOffset = RvaToVa((int) (tlsTable.AddressOfCallbacks - (long) Headers.PEHeader.ImageBase));
            }

            // Read the offsets of the TLS callbacks

            for (var tlsCallbackIndex = 0;; tlsCallbackIndex ++)
            {
                var tlsCallbackRva = Headers.PEHeader.Magic == PEMagic.PE32
                                   ? Unsafe.ReadUnaligned<int>(ref _peBytes[tlsCallbacksOffset + sizeof(int) * tlsCallbackIndex])
                                   : Unsafe.ReadUnaligned<long>(ref _peBytes[tlsCallbacksOffset + sizeof(long) * tlsCallbackIndex]);

                if (tlsCallbackRva == 0)
                {
                    break;
                }

                tlsCallbacks.Add(new TlsCallback((int) (tlsCallbackRva - (long) Headers.PEHeader.ImageBase)));
            }

            return tlsCallbacks;
        }

        private int RvaToVa(int rva)
        {
            var sectionHeader = Headers.SectionHeaders.First(section => section.VirtualAddress <= rva && section.VirtualAddress + section.VirtualSize > rva);

            return sectionHeader.PointerToRawData + (rva - sectionHeader.VirtualAddress);
        }
    }
}