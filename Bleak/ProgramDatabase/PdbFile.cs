using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Bleak.Native;
using Bleak.Native.PInvoke;
using Bleak.Native.Structures;
using Bleak.PortableExecutable.Structures;
using Bleak.RemoteProcess.Structures;

namespace Bleak.ProgramDatabase
{
    internal sealed class PdbFile
    {
        internal readonly Dictionary<string, IntPtr> Symbols;

        internal PdbFile(Module module, bool isWow64)
        {
            // Initialise a global mutex to ensure the PDB is only downloaded by a single instance at a time

            if (!Mutex.TryOpenExisting("BleakPdbMutex", out var pdbMutex))
            {
                pdbMutex = new Mutex(true, "BleakPdbMutex");
            }

            using (pdbMutex)
            {
                Symbols = ParseSymbols(DownloadPdb(module.PeImage.Value.DebugData, isWow64).Result, module.BaseAddress);

                pdbMutex.ReleaseMutex();
            }
        }

        private static async Task<string> DownloadPdb(DebugData debugData, bool isWow64)
        {
            // Ensure a directory exists on disk for the PDB

            var directoryInfo = Directory.CreateDirectory(isWow64 ? Path.Combine(Path.GetTempPath(), "Bleak", "PDB", "WOW64") : Path.Combine(Path.GetTempPath(), "Bleak", "PDB", "x64"));

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

            void ReportDownloadProgress(object sender, ProgressChangedEventArgs eventArgs)
            {
                var progress = eventArgs.ProgressPercentage / 2;

                Console.Write($"\rDownloading required files - [{new string('=', progress)}{new string(' ', 50 - progress)}] - {eventArgs.ProgressPercentage}%");
            }

            using var webClient = new WebClient();

            webClient.DownloadProgressChanged += ReportDownloadProgress;

            await webClient.DownloadFileTaskAsync(pdbUri, pdbPath);

            return pdbPath;
        }

        private static Dictionary<string, IntPtr> ParseSymbols(string pdbPath, IntPtr moduleAddress)
        {
            var symbols = new Dictionary<string, IntPtr>();

            // Initialise a symbol handler for the local process

            using var localProcess = Process.GetCurrentProcess();

            if (!Dbghelp.SymInitialize(localProcess.SafeHandle, IntPtr.Zero, false))
            {
                throw new Win32Exception($"Failed to call SymInitialize with error code {Marshal.GetLastWin32Error()}");
            }

            // Load the symbol table for the PDB

            var pdbPathBuffer = Encoding.Default.GetBytes(pdbPath);

            var symbolTableBaseAddress = Dbghelp.SymLoadModuleEx(localProcess.SafeHandle, IntPtr.Zero, ref pdbPathBuffer[0], IntPtr.Zero, moduleAddress, (int) new FileInfo(pdbPath).Length, IntPtr.Zero, 0);

            if (symbolTableBaseAddress == IntPtr.Zero)
            {
                throw new Win32Exception($"Failed to call SymLoadModuleEx with error code {Marshal.GetLastWin32Error()}");
            }

            // Initialise the callback used during the SymEnumSymbols call

            bool Callback(ref SymbolInfo symbolInfo, int symbolSize, IntPtr userContext)
            {
                var symbolNameBuffer = new byte[symbolInfo.NameLen];

                Unsafe.CopyBlockUnaligned(ref symbolNameBuffer[0], ref symbolInfo.Name, (uint) symbolNameBuffer.Length);

                symbols.TryAdd(Encoding.Default.GetString(symbolNameBuffer), (IntPtr) symbolInfo.Address);

                return true;
            }

            var callbackDelegate = new Prototypes.EnumerateSymbolsCallback(Callback);

            // Enumerate the PDB symbols

            if (!Dbghelp.SymEnumSymbols(localProcess.SafeHandle, symbolTableBaseAddress, IntPtr.Zero, callbackDelegate, IntPtr.Zero))
            {
                throw new Win32Exception($"Failed to call SymEnumSymbols with error code {Marshal.GetLastWin32Error()}");
            }

            if (!Dbghelp.SymUnloadModule(localProcess.SafeHandle, symbolTableBaseAddress))
            {
                throw new Win32Exception($"Failed to call SymUnloadModule with error code {Marshal.GetLastWin32Error()}");
            }

            return symbols;
        }
    }
}