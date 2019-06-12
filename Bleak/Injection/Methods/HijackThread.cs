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
    internal class HijackThread : IInjectionMethod
    {
        private readonly InjectionWrapper _injectionWrapper;

        public HijackThread(InjectionWrapper injectionWrapper)
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
            
            // Get the address of the LdrLoadDll function in the remote process
            
            var ldrLoadDllAddress = _injectionWrapper.ProcessManager.GetFunctionAddress("ntdll.dll", "LdrLoadDll");
            
            var returnBuffer = _injectionWrapper.MemoryManager.AllocateVirtualMemory(sizeof(uint));

            var moduleHandleBuffer = _injectionWrapper.MemoryManager.AllocateVirtualMemory(IntPtr.Size);
            
            // Write the shellcode used to call LdrLoadDll from a thread into the remote process

            var shellcode = _injectionWrapper.Assembler.AssembleThreadFunctionCall(CallingConvention.StdCall, ldrLoadDllAddress, returnBuffer,0, 0, (ulong) unicodeStringBuffer, (ulong) moduleHandleBuffer);
            
            var shellcodeBuffer = _injectionWrapper.MemoryManager.AllocateVirtualMemory(shellcode.Length);
            
            _injectionWrapper.MemoryManager.WriteVirtualMemory(shellcodeBuffer, shellcode);
            
            // Open a handle to the first thread in the remote process

            var firstThreadHandle = OpenThread(ThreadAccessMask.AllAccess, false, _injectionWrapper.ProcessManager.Process.Threads[0].Id);

            if (_injectionWrapper.ProcessManager.IsWow64)
            {
                // Suspend the thread

                if (Wow64SuspendThread(firstThreadHandle) == -1)
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to suspend a thread in the remote process");
                }

                var threadContextBuffer = Marshal.AllocHGlobal(Marshal.SizeOf<Wow64Context>());

                Marshal.StructureToPtr(new Wow64Context {ContextFlags = ContextFlags.Control}, threadContextBuffer, false);

                // Get the context of the thread

                if (!Wow64GetThreadContext(firstThreadHandle, threadContextBuffer))
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to get the context of a thread in the remote process");
                }

                var threadContext = Marshal.PtrToStructure<Wow64Context>(threadContextBuffer);

                // Write the original instruction pointer of the thread into the top of its stack

                threadContext.Esp -= sizeof(uint);

                _injectionWrapper.MemoryManager.WriteVirtualMemory((IntPtr) threadContext.Esp, threadContext.Eip);

                // Overwrite the instruction pointer of the thread with the address of the shellcode buffer

                threadContext.Eip = (uint) shellcodeBuffer;

                Marshal.StructureToPtr(threadContext, threadContextBuffer, true);

                // Update the context of the thread

                if (!Wow64SetThreadContext(firstThreadHandle, threadContextBuffer))
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to set the context of a thread in the remote process");
                }
            }

            else
            {
                // Suspend the thread

                if (SuspendThread(firstThreadHandle) == -1)
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to suspend a thread in the remote process");
                }

                var threadContextBuffer = Marshal.AllocHGlobal(Marshal.SizeOf<Context>());

                Marshal.StructureToPtr(new Context {ContextFlags = ContextFlags.Control}, threadContextBuffer, false);

                // Get the context of the thread

                if (!GetThreadContext(firstThreadHandle, threadContextBuffer))
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to get the context of a thread in the remote process");
                }

                var threadContext = Marshal.PtrToStructure<Context>(threadContextBuffer);

                // Write the original instruction pointer of the thread into the top of its stack

                threadContext.Rsp -= sizeof(ulong);

                _injectionWrapper.MemoryManager.WriteVirtualMemory((IntPtr) threadContext.Rsp, threadContext.Rip);

                // Overwrite the instruction pointer of the thread with the address of the shellcode buffer

                threadContext.Rip = (ulong) shellcodeBuffer;

                Marshal.StructureToPtr(threadContext, threadContextBuffer, true);

                // Update the context of the thread

                if (!SetThreadContext(firstThreadHandle, threadContextBuffer))
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to set the context of a thread in the remote process");
                }
            }
            
            // Flush the instruction cache of the remote process to ensure all memory operations have been completed

            if (!FlushInstructionCache(Process.GetCurrentProcess().SafeHandle, IntPtr.Zero, 0))
            {
                ExceptionHandler.ThrowWin32Exception("Failed to flush the instruction cache of the remote process");
            }
            
            // Resume the thread

            if (ResumeThread(firstThreadHandle) == -1)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to resume a thread in the remote process");
            }

            firstThreadHandle.Dispose();
            
            // Send a message to the thread to ensure it resumes

            PostThreadMessage(_injectionWrapper.ProcessManager.Process.Threads[0].Id, WindowsMessage.Keydown, VirtualKey.LeftButton, IntPtr.Zero);
            
            // Read the returned value of LdrLoadDll from the buffer

            var ntStatus = _injectionWrapper.MemoryManager.ReadVirtualMemory<uint>(returnBuffer);

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