using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Bleak.Native.Enumerations;
using Bleak.Native.Structures;
using Bleak.PortableExecutable;
using Bleak.RemoteProcess;
using Bleak.Memory;

namespace Bleak.Injection
{
    internal abstract class InjectionBase : IDisposable
    {
        internal IntPtr DllBaseAddress;

        protected readonly byte[] DllBytes;

        protected readonly string DllPath;

        protected readonly InjectionFlags InjectionFlags;

        protected readonly PeImage PeImage;

        protected readonly ProcessManager ProcessManager;

        private IntPtr _dllEntryAddress;

        protected InjectionBase(byte[] dllBytes, Process process, InjectionFlags injectionFlags)
        {
            DllBytes = dllBytes;

            InjectionFlags = injectionFlags;

            PeImage = new PeImage(dllBytes);

            ProcessManager = new ProcessManager(process);
        }

        protected InjectionBase(string dllPath, Process process, InjectionFlags injectionFlags)
        {
            DllBytes = File.ReadAllBytes(dllPath);

            DllPath = dllPath;

            InjectionFlags = injectionFlags;

            PeImage = new PeImage(DllBytes);

            ProcessManager = new ProcessManager(process);
        }

        public void Dispose()
        {
            ProcessManager.Dispose();
        }

        internal void HideDllFromPeb()
        {
            if (_dllEntryAddress == IntPtr.Zero)
            {
                if (ProcessManager.IsWow64)
                {
                    foreach (var (entryAddress, entry) in ProcessManager.PebManager.GetWow64PebEntries())
                    {
                        // Read the file path of the entry

                        var entryFilePathBytes = MemoryManager.ReadVirtualMemory(ProcessManager.Process.SafeHandle, (IntPtr) entry.FullDllName.Buffer, entry.FullDllName.Length);

                        var entryFilePath = Encoding.Unicode.GetString(entryFilePathBytes);

                        if (entryFilePath != DllPath)
                        {
                            continue;
                        }

                        _dllEntryAddress = entryAddress;
                    }
                }

                else
                {
                    foreach (var (entryAddress, entry) in ProcessManager.PebManager.GetPebEntries())
                    {
                        // Read the file path of the entry

                        var entryFilePathBytes = MemoryManager.ReadVirtualMemory(ProcessManager.Process.SafeHandle, (IntPtr) entry.FullDllName.Buffer, entry.FullDllName.Length);

                        var entryFilePath = Encoding.Unicode.GetString(entryFilePathBytes);

                        if (entryFilePath != DllPath)
                        {
                            continue;
                        }

                        _dllEntryAddress = entryAddress;
                    }
                }
            }

            // Unlink the DLL from the PEB

            ProcessManager.PebManager.UnlinkEntryFromPeb(_dllEntryAddress);

            // Remove the entry for the DLL from the LdrpModuleBaseAddressIndex

            var rtlRbRemoveNodeAddress = ProcessManager.GetFunctionAddress("ntdll.dll", "RtlRbRemoveNode");

            var ldrpModuleBaseAddressIndex = ProcessManager.PdbFile.Value.Symbols["LdrpModuleBaseAddressIndex"];

            ProcessManager.CallFunction(CallingConvention.StdCall, rtlRbRemoveNodeAddress, (long) ldrpModuleBaseAddressIndex, (long) (_dllEntryAddress + (int) Marshal.OffsetOf<LdrDataTableEntry64>("BaseAddressIndexNode")));
        }

        internal IntPtr InitialiseDllPath()
        {
            // Write the DLL path into the remote process

            var dllPathAddress = MemoryManager.AllocateVirtualMemory(ProcessManager.Process.SafeHandle, IntPtr.Zero, DllPath.Length, MemoryProtectionType.ReadWrite);

            MemoryManager.WriteVirtualMemory(ProcessManager.Process.SafeHandle, dllPathAddress, Encoding.Unicode.GetBytes(DllPath));

            // Write a UnicodeString representing the DLL path into the remote process

            IntPtr dllPathUnicodeStringAddress;

            if (ProcessManager.IsWow64)
            {
                var dllPathUnicodeString = new UnicodeString32(DllPath, dllPathAddress);

                dllPathUnicodeStringAddress = MemoryManager.AllocateVirtualMemory(ProcessManager.Process.SafeHandle, IntPtr.Zero, Marshal.SizeOf<UnicodeString32>(), MemoryProtectionType.ReadWrite);

                MemoryManager.WriteVirtualMemory(ProcessManager.Process.SafeHandle, dllPathUnicodeStringAddress, dllPathUnicodeString);
            }

            else
            {
                var dllPathUnicodeString = new UnicodeString64(DllPath, dllPathAddress);

                dllPathUnicodeStringAddress = MemoryManager.AllocateVirtualMemory(ProcessManager.Process.SafeHandle, IntPtr.Zero, Marshal.SizeOf<UnicodeString64>(), MemoryProtectionType.ReadWrite);

                MemoryManager.WriteVirtualMemory(ProcessManager.Process.SafeHandle, dllPathUnicodeStringAddress, dllPathUnicodeString);
            }

            return dllPathUnicodeStringAddress;
        }

        internal void RandomiseDllHeaders(IntPtr dllAddress)
        {
            // Write over the header region of the DLL with random bytes

            var randomBuffer = new byte[PeImage.PeHeaders.PEHeader.SizeOfHeaders];

            new Random().NextBytes(randomBuffer);

            MemoryManager.WriteVirtualMemory(ProcessManager.Process.SafeHandle, dllAddress, randomBuffer);
        }

        internal abstract void Eject();

        internal abstract void Inject();
    }
}