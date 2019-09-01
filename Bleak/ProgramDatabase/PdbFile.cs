using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Bleak.Exceptions;
using Bleak.Native;
using Bleak.Native.PInvoke;
using Bleak.Native.Structures;
using Bleak.PortableExecutable;
using Bleak.RemoteProcess;

namespace Bleak.ProgramDatabase
{
    internal class PdbFile
    {
        internal readonly Dictionary<string, IntPtr> Symbols;

        internal PdbFile(Module module, bool isWow64)
        {
            Symbols = ParseSymbols(DownloadPdb(new PeImage(File.ReadAllBytes(module.FilePath)).PdbDebugData, isWow64).Result, module.BaseAddress);
        }

        private async Task<string> DownloadPdb(PdbDebugData pdbDebugData, bool isWow64)
        {
            // Ensure a directory exists on disk for the PDB

            var directoryInfo = Directory.CreateDirectory(isWow64 ? Path.Combine(Path.GetTempPath(), "Bleak", "PDB", "WOW64") : Path.Combine(Path.GetTempPath(), "Bleak", "PDB", "x64"));

            var pdbName = $"{pdbDebugData.Name}-{pdbDebugData.Guid}-{pdbDebugData.Age}.pdb";

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

            var pdbUri = new Uri($"http://msdl.microsoft.com/download/symbols/{pdbDebugData.Name}/{pdbDebugData.Guid}{pdbDebugData.Age}/{pdbDebugData.Name}");

            void ReportDownloadProgress(object sender, ProgressChangedEventArgs eventArgs)
            {
                var progress = eventArgs.ProgressPercentage / 2;

                Console.Write($"\rDownloading required files - [{new string('=', progress)}{new string(' ', 50 - progress)}] - {eventArgs.ProgressPercentage}%");
            }

            using (var webClient = new WebClient())
            {
                webClient.DownloadProgressChanged += ReportDownloadProgress;

                await webClient.DownloadFileTaskAsync(pdbUri, pdbPath);
            }

            return pdbPath;
        }

        private Dictionary<string, IntPtr> ParseSymbols(string pdbPath, IntPtr moduleAddress)
        {
            // Initialise a symbol handler for the local process

            var localProcessHandle = Process.GetCurrentProcess().SafeHandle;

            if (!Dbghelp.SymInitialize(localProcessHandle, IntPtr.Zero, false))
            {
                throw new PInvokeException("Failed to call SymInitialize");
            }

            // Load the symbol table for the PDB

            var pdbPathBuffer = Marshal.StringToHGlobalAnsi(pdbPath);

            var symbolTableBaseAddress = Dbghelp.SymLoadModuleEx(localProcessHandle, IntPtr.Zero, pdbPathBuffer, IntPtr.Zero, moduleAddress, int.MaxValue, IntPtr.Zero, 0);

            if (symbolTableBaseAddress == IntPtr.Zero)
            {
                throw new PInvokeException("Failed to call SymLoadModuleEx");
            }

            // Initialise the callback used during the SymEnumSymbols call

            var symbols = new Dictionary<string, IntPtr>();

            bool Callback(IntPtr symbolInfo, int symbolSize, IntPtr userContext)
            {
                symbols.TryAdd(Marshal.PtrToStringAnsi(symbolInfo + Marshal.SizeOf<SymbolInfo>()), (IntPtr) Marshal.PtrToStructure<SymbolInfo>(symbolInfo).Address);

                return true;
            }

            var callbackDelegate = new Prototypes.EnumerateSymbolsCallback(Callback);

            var callbackPointer = Marshal.GetFunctionPointerForDelegate(callbackDelegate);

            // Enumerate the PDB symbols

            if (!Dbghelp.SymEnumSymbols(localProcessHandle, symbolTableBaseAddress, IntPtr.Zero, callbackPointer, IntPtr.Zero))
            {
                throw new PInvokeException("Failed to call SymEnumSymbols");
            }

            Dbghelp.SymUnloadModule64(localProcessHandle, symbolTableBaseAddress);

            return symbols;
        }
    }
}