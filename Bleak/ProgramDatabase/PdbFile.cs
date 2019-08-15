using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Bleak.Native;
using Bleak.Native.PInvoke;
using Bleak.Native.Structures;
using Bleak.Network;
using Bleak.RemoteProcess;
using Bleak.Shared.Exceptions;

namespace Bleak.ProgramDatabase
{
    internal class PdbFile
    {
        internal readonly Dictionary<string, IntPtr> Symbols;
        
        private readonly ManagedModule _module;
        
        internal PdbFile(ManagedModule module, bool isWow64)
        {
            _module = module;

            Symbols = ParseSymbols(isWow64).Result;
        }

        private async Task<string> DownloadPdb(bool isWow64)
        {
            // Ensure a directory exists on disk for the PDB

            var directoryInfo = Directory.CreateDirectory(isWow64 ? Path.Combine(Path.GetTempPath(), "Bleak", "PDB", "WOW64") : Path.Combine(Path.GetTempPath(), "Bleak", "PDB", "x64"));

            var debugData = _module.PeImage.Value.DebugData.Value;
            
            var pdbName = $"{debugData.Name}-{debugData.Guid}-{debugData.Age}.pdb";
            
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
            
            var pdbUri = new Uri($"http://msdl.microsoft.com/download/symbols/{debugData.Name}/{debugData.Guid}{debugData.Age}/{debugData.Name}");

            await FileDownloader.DownloadFile(pdbUri, pdbPath);

            return pdbPath;
        }

        private async Task<Dictionary<string, IntPtr>> ParseSymbols(bool isWow64)
        {
            // Initialise a symbol handler for the local process
            
            var localProcessHandle = Process.GetCurrentProcess().SafeHandle;
            
            if (!Dbghelp.SymInitialize(localProcessHandle, IntPtr.Zero, false))
            {
                throw new PInvokeException("Failed to call SymInitialize");
            }
            
            // Load the symbol table for the PDB
            
            var pdbPathBuffer = Marshal.StringToHGlobalAnsi(await DownloadPdb(isWow64));

            var symbolTableBaseAddress = Dbghelp.SymLoadModuleEx(localProcessHandle, IntPtr.Zero, pdbPathBuffer, IntPtr.Zero, _module.BaseAddress, int.MaxValue, IntPtr.Zero, 0);
            
            if (symbolTableBaseAddress == IntPtr.Zero)
            {
                throw new PInvokeException("Failed to call SymLoadModuleEx");
            }
            
            // Initialise the callback used during SymEnumSymbols

            var symbolAddresses = new List<IntPtr>();
            
            var symbolNames = new List<string>();
            
            bool Callback(IntPtr symbolInfo, int symbolSize, IntPtr userContext)
            {
                symbolAddresses.Add((IntPtr) Marshal.PtrToStructure<SymbolInfo>(symbolInfo).Address);
                
                symbolNames.Add(Marshal.PtrToStringAnsi(symbolInfo + Marshal.SizeOf<SymbolInfo>()));
                
                return true;
            }

            var callBackPointer = Marshal.GetFunctionPointerForDelegate(new Callbacks.EnumerateSymbolsCallback(Callback));
            
            // Enumerate the PDB symbols

            if (!Dbghelp.SymEnumSymbols(localProcessHandle, symbolTableBaseAddress, IntPtr.Zero, callBackPointer, IntPtr.Zero))
            {
                throw new PInvokeException("Failed to call SymEnumSymbols");
            }
            
            Dbghelp.SymUnloadModule64(localProcessHandle, symbolTableBaseAddress);

            var symbols = new Dictionary<string, IntPtr>();
            
            for (var symbolIndex = 0; symbolIndex < symbolNames.Count; symbolIndex ++)
            {
                symbols.TryAdd(symbolNames[symbolIndex], symbolAddresses[symbolIndex]);
            }

            return symbols;
        }
    }
}