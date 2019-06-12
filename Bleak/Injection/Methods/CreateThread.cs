using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using Bleak.Injection.Interfaces;
using Bleak.Injection.Objects;
using Bleak.Shared.Handlers;
using static Bleak.Native.Enumerations;
using static Bleak.Native.PInvoke;
using static Bleak.Native.Structures;

namespace Bleak.Injection.Methods
{
    internal class CreateThread : IInjectionMethod
    {
        private readonly InjectionWrapper _injectionWrapper;

        public CreateThread(InjectionWrapper injectionWrapper)
        {
            _injectionWrapper = injectionWrapper;
        }
        
        public IntPtr Call()
        {
            // Write the DLL path into the remote process

            var dllPathBuffer = _injectionWrapper.MemoryManager.AllocateVirtualMemory(_injectionWrapper.DllPath.Length);

            var dllPathBytes = Encoding.Unicode.GetBytes(_injectionWrapper.DllPath);

            _injectionWrapper.MemoryManager.WriteVirtualMemory(dllPathBuffer, dllPathBytes);
            
            // Write a UnicodeString representing the DLL path into the remote process

            IntPtr unicodeStringBuffer;

            if (_injectionWrapper.ProcessManager.IsWow64)
            {
                var unicodeString = new UnicodeString32(_injectionWrapper.DllPath)
                {
                    Buffer = (uint) dllPathBuffer
                };

                unicodeStringBuffer = _injectionWrapper.MemoryManager.AllocateVirtualMemory(Marshal.SizeOf<UnicodeString32>());

                _injectionWrapper.MemoryManager.WriteVirtualMemory(unicodeStringBuffer, unicodeString);
            }

            else
            {
                var unicodeString = new UnicodeString64(_injectionWrapper.DllPath)
                {
                    Buffer = (ulong) dllPathBuffer
                };

                unicodeStringBuffer = _injectionWrapper.MemoryManager.AllocateVirtualMemory(Marshal.SizeOf<UnicodeString64>());

                _injectionWrapper.MemoryManager.WriteVirtualMemory(unicodeStringBuffer, unicodeString);
            }
            
            var moduleHandleBuffer = _injectionWrapper.MemoryManager.AllocateVirtualMemory(IntPtr.Size);
            
            // Flush the instruction cache of the remote process to ensure all memory operations have been completed

            if (!FlushInstructionCache(Process.GetCurrentProcess().SafeHandle, IntPtr.Zero, 0))
            {
                ExceptionHandler.ThrowWin32Exception("Failed to flush the instruction cache of the remote process");
            }
            
            // Call LdrLoadDll in the remote process
            
            var ldrLoadDllAddress = _injectionWrapper.ProcessManager.GetFunctionAddress("ntdll.dll", "LdrLoadDll");
            
            var ntStatus = _injectionWrapper.ProcessManager.CallFunction<uint>(CallingConvention.StdCall, ldrLoadDllAddress, 0, 0, (ulong) unicodeStringBuffer, (ulong) moduleHandleBuffer);

            if ((NtStatus) ntStatus != NtStatus.Success)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to call LdrLoadDll in the remote process", (NtStatus) ntStatus);
            }
            
            while (_injectionWrapper.ProcessManager.Modules.All(module => module.FilePath != _injectionWrapper.DllPath))
            {
                _injectionWrapper.ProcessManager.Refresh();
            }
            
            _injectionWrapper.MemoryManager.FreeVirtualMemory(dllPathBuffer);

            _injectionWrapper.MemoryManager.FreeVirtualMemory(unicodeStringBuffer);
            
            try
            {
                // Read the base address of the DLL that was loaded in the remote process

                return _injectionWrapper.MemoryManager.ReadVirtualMemory<IntPtr>(moduleHandleBuffer);
            }

            finally
            {
                _injectionWrapper.MemoryManager.FreeVirtualMemory(moduleHandleBuffer);
            }
        }
    }
}