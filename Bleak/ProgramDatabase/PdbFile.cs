using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Bleak.Native;
using Bleak.Native.Structures;
using Bleak.Network;
using Bleak.ProgramDatabase.Objects;
using Bleak.RemoteProcess.Objects;

namespace Bleak.ProgramDatabase
{
    internal class PdbFile
    {
        private readonly Module _module;
        
        private readonly List<Symbol> _symbols;

        internal PdbFile(Module module, bool isWow64)
        {
            _module = module;
            
            _symbols = ParseSymbols(isWow64).Result;
        }
        
        internal IntPtr GetSymbolAddress(Regex symbolRegex)
        {
            var symbol = _symbols.Find(s => symbolRegex.IsMatch(s.Name));

            var symbolSection = _module.PeImage.Value.PeHeaders.SectionHeaders[symbol.Section - 1];

            return _module.BaseAddress + (symbolSection.VirtualAddress + symbol.Offset);
        }

        private async Task<string> DownloadPdb(bool isWow64)
        {
            // Ensure a directory exists on disk for the PDB

            var directoryInfo = Directory.CreateDirectory(isWow64 ? Path.Combine(Path.GetTempPath(), "Bleak", "PDB", "WOW64") : Path.Combine(Path.GetTempPath(), "Bleak", "PDB", "x64"));

            var debugData = _module.PeImage.Value.DebugData.Value;
            
            var pdbName = $"{debugData.Path}-{debugData.Guid}-{debugData.Age}.pdb";
            
            var pdbPath = Path.Combine(directoryInfo.FullName, pdbName);
            
            // Determine if the PDB has already been downloaded
            
            if (directoryInfo.EnumerateFiles().Any(file => file.Name == pdbName))
            {
                return pdbPath;
            }
            
            // Clear the directory

            foreach (var file in directoryInfo.EnumerateFiles())
            {
                try
                {
                    file.Delete();
                }

                catch (Exception)
                {
                    // The file is currently open and cannot be safely deleted
                }
            }
            
            // Download the PDB
            
            var pdbUri = new Uri($"http://msdl.microsoft.com/download/symbols/{debugData.Path}/{debugData.Guid.ToString().Replace("-", "")}{debugData.Age}/{debugData.Path}");

            await FileDownloader.DownloadFile(pdbUri, pdbPath);

            return pdbPath;
        }

        private async Task<List<Symbol>> ParseSymbols(bool isWow64)
        {
            var symbols = new List<Symbol>();

            // Read the PDB header

            var pdbBytes = File.ReadAllBytes(await DownloadPdb(isWow64));

            var pdbBuffer = Marshal.AllocHGlobal(pdbBytes.Length);
            
            Marshal.Copy(pdbBytes, 0, pdbBuffer, pdbBytes.Length);
            
            var pdbHeader = Marshal.PtrToStructure<PdbHeader>(pdbBuffer);
            
            // Read the root stream

            var rootPageNumber = Marshal.ReadInt32(pdbBuffer + pdbHeader.PageSize * pdbHeader.RootStreamPageNumberListNumber);

            var rootStream = Marshal.ReadInt32(pdbBuffer + pdbHeader.PageSize * rootPageNumber);
            
            // Read the remaining streams

            var streamSizes = new int[rootStream];
            
            Marshal.Copy(pdbBuffer + pdbHeader.PageSize * rootPageNumber + sizeof(int), streamSizes, 0, rootStream);
            
            var streams = new List<List<int>>();
            
            var pageNumber = 0;

            foreach (var streamSize in streamSizes)
            {
                // Calculate the amount of pages in the stream
                 
                var pagesNeeded = streamSize / pdbHeader.PageSize;
                 
                if (streamSize % pdbHeader.PageSize != 0)
                {
                    pagesNeeded += 1;
                }
                
                // Read the pages of the stream
                
                var streamPages = new List<int>();

                for (var pageIndex = 0; pageIndex < pagesNeeded; pageIndex += 1)
                {
                    streamPages.Add(Marshal.ReadInt32(pdbBuffer + pdbHeader.PageSize * rootPageNumber + sizeof(int) + (rootStream + pageNumber) * sizeof(int)));
                    
                    pageNumber += 1;
                }
                
                streams.Add(streamPages);
            }
            
            // Read the DBI header

            var dbiHeader = Marshal.PtrToStructure<DbiHeader>(pdbBuffer + pdbHeader.PageSize * streams[3][0]);
            
            Marshal.FreeHGlobal(pdbBuffer);
            
            // Read the symbol stream
            
            var symbolStream = new byte[pdbHeader.PageSize * streams[dbiHeader.SymbolStreamIndex].Count];
            
            for (var pageIndex = 0; pageIndex < streams[dbiHeader.SymbolStreamIndex].Count; pageIndex += 1)
            {
                Buffer.BlockCopy(pdbBytes, pdbHeader.PageSize * streams[dbiHeader.SymbolStreamIndex][pageIndex], symbolStream, pdbHeader.PageSize * pageIndex, pdbHeader.PageSize);
            }

            var symbolStreamBuffer = Marshal.AllocHGlobal(symbolStream.Length);
            
            Marshal.Copy(symbolStream, 0,symbolStreamBuffer, symbolStream.Length);
            
            // Read the symbols
            
            var currentSymbolOffset = 0;
            
            while (true)
            {
                // Read the name of the symbol

                var symbolData = Marshal.PtrToStructure<SymbolData>(symbolStreamBuffer + currentSymbolOffset);

                if (symbolData.Magic != Constants.SymbolMagic)
                { 
                    break;
                }

                var symbolName = Marshal.PtrToStringAnsi(symbolStreamBuffer + currentSymbolOffset + Marshal.SizeOf<SymbolData>());

                symbols.Add(new Symbol(symbolName, symbolData.Offset, symbolData.Section));
                 
                // Calculate the offset of the next symbol

                currentSymbolOffset += symbolData.Length + sizeof(short);
            }
            
            return symbols;
        }
    }
}