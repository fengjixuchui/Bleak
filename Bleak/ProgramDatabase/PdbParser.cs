using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Bleak.ProgramDatabase.Objects;
using Bleak.RemoteProcess.Objects;
using Bleak.Shared;
using static Bleak.Native.Structures;
using static Bleak.Native.Constants;

namespace Bleak.ProgramDatabase
{
    internal class PdbParser
    {
        internal readonly Module Module;
        
        internal readonly List<PdbSymbol> PdbSymbols;

        private string _pdbPath;

        internal PdbParser(Module module)
        {
            Module = module;
            
            PdbSymbols = GetPdbSymbols().Result;
        }

        private async Task DownloadPdb()
        {
            var debugData = Module.PeParser.Value.DebugData;
            
            // Create the URI for the PDB

            var pdbUri = new Uri($"http://msdl.microsoft.com/download/symbols/{debugData.Path}/{debugData.Guid.ToString().Replace("-", "")}{debugData.Age}/{debugData.Path}");

            // Ensure a directory exists on disk for the PDB

            var directoryInfo = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "Bleak", "PDB"));

            var pdbName = $"{debugData.Path}-{debugData.Guid}-{debugData.Age}.pdb";

            _pdbPath = Path.Combine(directoryInfo.FullName, pdbName);

            // Ensure the PDB hasn't already been downloaded

            var webRequest = WebRequest.Create(pdbUri);

            webRequest.Method = "HEAD";

            using (var webResponse = webRequest.GetResponse())
            {
                if (directoryInfo.EnumerateFiles().Any(file => file.Name == pdbName && file.Length == webResponse.ContentLength))
                {
                    return;
                }
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

            // Ensure the microsoft symbol server can be accessed
            
            if (new Ping().Send("msdl.microsoft.com")?.Status != IPStatus.Success)
            {
                throw new WebException("Failed to ping the Microsoft symbol server");
            }

            using (var webClient = new WebClient())
            {
                await webClient.DownloadFileTaskAsync(pdbUri, _pdbPath);
            }
        }

        private async Task<List<PdbSymbol>> GetPdbSymbols()
        {
            var pdbSymbols = new List<PdbSymbol>();
            
            await DownloadPdb();

            // Read the PDB header
            
            var pdbBufferHandle = GCHandle.Alloc(File.ReadAllBytes(_pdbPath), GCHandleType.Pinned);

            var pdbBuffer = pdbBufferHandle.AddrOfPinnedObject();
            
            var pdbHeader = Marshal.PtrToStructure<PdbHeader>(pdbBuffer);
            
            // Determine the amount of streams in the PDB
            
            var rootPageNumber = Marshal.PtrToStructure<uint>(pdbBuffer.AddOffset(pdbHeader.PageSize * pdbHeader.RootStreamPageNumberListNumber));
            
            var rootStream = Marshal.PtrToStructure<uint>(pdbBuffer.AddOffset(pdbHeader.PageSize * rootPageNumber));
            
            var streams = new List<List<uint>>();
            
            var pageNumber = 0;
            
            for (var streamIndex = 0; streamIndex < rootStream; streamIndex += 1)
            {
                // Calculate the amount of pages in the stream
                
                var streamSize = Marshal.PtrToStructure<uint>(pdbBuffer.AddOffset(pdbHeader.PageSize * rootPageNumber + sizeof(uint) + sizeof(uint) * streamIndex));
                
                var pagesNeeded = streamSize / pdbHeader.PageSize;

                if (streamSize % pdbHeader.PageSize != 0)
                {
                    pagesNeeded += 1;
                }
                
                var streamPages = new List<uint>();

                for (var pageIndex = 0; pageIndex < pagesNeeded; pageIndex += 1)
                {
                    // Read the page of the stream

                    streamPages.Add(Marshal.PtrToStructure<uint>(pdbBuffer.AddOffset(pdbHeader.PageSize * rootPageNumber + sizeof(uint) + (rootStream + pageNumber) * sizeof(uint))));

                    pageNumber += 1;
                }
                
                streams.Add(streamPages); 
            }
            
            // Read the DBI header
            
            var dbiStreamOffset = pdbHeader.PageSize * streams[3][0];
            
            var dbiHeader = Marshal.PtrToStructure<DbiHeader>(pdbBuffer.AddOffset(dbiStreamOffset));
            
            // Get the symbol stream

            var symbolStream = new byte[pdbHeader.PageSize * streams[dbiHeader.SymbolStreamIndex].Count];

            for (var pageIndex = 0; pageIndex < streams[dbiHeader.SymbolStreamIndex].Count; pageIndex += 1)
            {
                Marshal.Copy(pdbBuffer.AddOffset(pdbHeader.PageSize * streams[dbiHeader.SymbolStreamIndex][pageIndex]), symbolStream, (int) pdbHeader.PageSize * pageIndex, (int) pdbHeader.PageSize);
            }
            
            pdbBufferHandle.Free();

            var symbolStreamBufferHandle = GCHandle.Alloc(symbolStream, GCHandleType.Pinned);

            var symbolStreamBuffer = symbolStreamBufferHandle.AddrOfPinnedObject();

            while (true)
            {
                // Read the name of the symbol
                
                var symbolData = Marshal.PtrToStructure<SymbolData>(symbolStreamBuffer);
                
                if (symbolData.Magic != SymbolMagic)
                {
                    break;
                }
                
                var symbolName = Marshal.PtrToStringAnsi(symbolStreamBuffer.AddOffset(Marshal.SizeOf<SymbolData>()));
                
                pdbSymbols.Add(new PdbSymbol(symbolName, symbolData.Offset, symbolData.Section));
                
                // Calculate the address of the next symbol
                
                symbolStreamBuffer += symbolData.Length + sizeof(ushort);
            }
            
            symbolStreamBufferHandle.Free();
            
            return pdbSymbols;
        }
    }
}