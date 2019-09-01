using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Bleak.Exceptions;
using Bleak.Native.Enumerations;
using Bleak.Native.Structures;
using Bleak.Memory;

namespace Bleak.Injection.Methods
{
    internal class CreateThread : InjectionBase
    {
        public CreateThread(string dllPath, Process process, InjectionFlags injectionFlags) : base(dllPath, process, injectionFlags) { }

        internal override void Eject()
        {
            if (InjectionFlags.HasFlag(InjectionFlags.HideDllFromPeb))
            {
                return;
            }

            var freeLibraryAddress = ProcessManager.GetFunctionAddress("kernel32.dll", "FreeLibrary");

            if (!ProcessManager.CallFunction<bool>(CallingConvention.StdCall, freeLibraryAddress, (long) DllBaseAddress))
            {
                throw new RemoteFunctionCallException("Failed to call FreeLibrary");
            }
        }

        internal override void Inject()
        {
            // Write the DLL path into the remote process

            var dllPathUnicodeStringAddress = InitialiseDllPath();

            // Create a thread to call LdrLoadDll in the remote process

            var ldrLoadDllAddress = ProcessManager.GetFunctionAddress("ntdll.dll", "LdrLoadDll");

            var moduleHandleAddress = MemoryManager.AllocateVirtualMemory(ProcessManager.Process.SafeHandle, IntPtr.Zero, IntPtr.Size, MemoryProtectionType.ReadWrite);

            var ntStatus = ProcessManager.CallFunction<int>(CallingConvention.StdCall, ldrLoadDllAddress, 0, 0, (long) dllPathUnicodeStringAddress, (long) moduleHandleAddress);

            if ((NtStatus) ntStatus != NtStatus.Success)
            {
                throw new RemoteFunctionCallException("Failed to call LdrLoadDll", (NtStatus) ntStatus);
            }

            // Ensure the DLL is loaded before freeing any memory

            while (ProcessManager.Modules.TrueForAll(module => module.FilePath != DllPath))
            {
                ProcessManager.Refresh();
            }

            var dllPathAddress = ProcessManager.IsWow64 ? (IntPtr) MemoryManager.ReadVirtualMemory<UnicodeString32>(ProcessManager.Process.SafeHandle, dllPathUnicodeStringAddress).Buffer
                                                        : (IntPtr) MemoryManager.ReadVirtualMemory<UnicodeString64>(ProcessManager.Process.SafeHandle, dllPathUnicodeStringAddress).Buffer;

            MemoryManager.FreeVirtualMemory(ProcessManager.Process.SafeHandle, dllPathAddress);

            MemoryManager.FreeVirtualMemory(ProcessManager.Process.SafeHandle, dllPathUnicodeStringAddress);

            // Read the address of the DLL that was loaded in the remote process

            DllBaseAddress = MemoryManager.ReadVirtualMemory<IntPtr>(ProcessManager.Process.SafeHandle, moduleHandleAddress);

            MemoryManager.FreeVirtualMemory(ProcessManager.Process.SafeHandle, moduleHandleAddress);

            if (InjectionFlags.HasFlag(InjectionFlags.HideDllFromPeb))
            {
                // Hide the DLL from the PEB of the remote process

                HideDllFromPeb();
            }

            if (InjectionFlags.HasFlag(InjectionFlags.RandomiseDllHeaders))
            {
                // Randomise the DLL headers

                RandomiseDllHeaders(DllBaseAddress);
            }
        }
    }
}