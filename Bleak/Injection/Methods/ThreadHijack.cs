using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using Bleak.Handlers;
using Bleak.Injection.Interfaces;
using Bleak.Injection.Objects;
using Bleak.Injection.Tools;
using Bleak.Native;

namespace Bleak.Injection.Methods
{
    internal class ThreadHijack : IInjectionMethod
    {
        private readonly InjectionTools _injectionTools;

        private readonly InjectionWrapper _injectionWrapper;

        public ThreadHijack(InjectionWrapper injectionWrapper)
        {
            _injectionTools = new InjectionTools(injectionWrapper);

            _injectionWrapper = injectionWrapper;
        }

        public IntPtr Call()
        {
            // Write the DLL path into the remote process

            var dllPathBuffer = _injectionWrapper.MemoryManager.AllocateVirtualMemory(_injectionWrapper.DllPath.Length);

            var dllPathBytes = Encoding.Unicode.GetBytes(_injectionWrapper.DllPath);

            _injectionWrapper.MemoryManager.WriteVirtualMemory(dllPathBuffer, dllPathBytes);

            // Write a UnicodeString representing the DLL path into the remote process

            var unicodeStringBuffer = _injectionTools.CreateRemoteUnicodeString(dllPathBuffer);

            // Get the address of the LdrLoadDll function in the remote process

            var ldrLoadDllAddress = _injectionWrapper.RemoteProcess.GetFunctionAddress("ntdll.dll", "LdrLoadDll");

            // Write the shellcode used to call LdrLoadDll from a thread into the remote process

            var moduleHandleBuffer = _injectionWrapper.MemoryManager.AllocateVirtualMemory<IntPtr>();

            var shellcode = _injectionWrapper.Assembler.AssembleThreadHijackFunctionCall(ldrLoadDllAddress, 0, 0, (ulong) unicodeStringBuffer, (ulong) moduleHandleBuffer);

            var shellcodeBuffer = _injectionWrapper.MemoryManager.AllocateVirtualMemory(shellcode.Length);

            _injectionWrapper.MemoryManager.WriteVirtualMemory(shellcodeBuffer, shellcode);

            // Open a handle to the first thread in the remote process

            var firstThreadHandle = PInvoke.OpenThread(Enumerations.ThreadAccessMask.AllAccess, false, _injectionWrapper.RemoteProcess.Process.Threads[0].Id);

            if (_injectionWrapper.RemoteProcess.IsWow64)
            {
                // Suspend the thread

                if (PInvoke.Wow64SuspendThread(firstThreadHandle) == -1)
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to suspend a thread in the remote process");
                }

                // Get the context of the thread

                var threadContextBuffer = Marshal.AllocHGlobal(Marshal.SizeOf<Structures.Wow64Context>());

                Marshal.StructureToPtr(new Structures.Wow64Context { ContextFlags = Enumerations.ContextFlags.Control }, threadContextBuffer, false);

                if (!PInvoke.Wow64GetThreadContext(firstThreadHandle, threadContextBuffer))
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to get the context of a thread in the remote process");
                }

                var threadContext = Marshal.PtrToStructure<Structures.Wow64Context>(threadContextBuffer);

                // Write the original instruction pointer of the thread into its stack

                threadContext.Esp -= sizeof(uint);

                _injectionWrapper.MemoryManager.WriteVirtualMemory((IntPtr) threadContext.Esp, threadContext.Eip);

                // Overwrite the instruction pointer of the thread with the address of the shellcode buffer

                threadContext.Eip = (uint) shellcodeBuffer;

                Marshal.StructureToPtr(threadContext, threadContextBuffer, true);

                // Update the context of the thread

                if (!PInvoke.Wow64SetThreadContext(firstThreadHandle, threadContextBuffer))
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to set the context of a thread in the remote process");
                }

                Marshal.FreeHGlobal(threadContextBuffer);
            }

            else
            {
                // Suspend the thread

                if (PInvoke.SuspendThread(firstThreadHandle) == -1)
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to suspend a thread in the remote process");
                }

                // Get the context of the thread

                var threadContextBuffer = Marshal.AllocHGlobal(Marshal.SizeOf<Structures.Context>());

                Marshal.StructureToPtr(new Structures.Context { ContextFlags = Enumerations.ContextFlags.Control }, threadContextBuffer, false);

                if (!PInvoke.GetThreadContext(firstThreadHandle, threadContextBuffer))
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to get the context of a thread in the remote process");
                }

                var threadContext = Marshal.PtrToStructure<Structures.Context>(threadContextBuffer);

                // Write the original instruction pointer of the thread into its stack

                threadContext.Rsp -= sizeof(ulong);

                _injectionWrapper.MemoryManager.WriteVirtualMemory((IntPtr) threadContext.Rsp, threadContext.Rip);

                // Overwrite the instruction pointer of the thread with the address of the shellcode buffer

                threadContext.Rip = (ulong) shellcodeBuffer;

                Marshal.StructureToPtr(threadContext, threadContextBuffer, true);

                // Update the context of the thread

                if (!PInvoke.SetThreadContext(firstThreadHandle, threadContextBuffer))
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to set the context of a thread in the remote process");
                }

                Marshal.FreeHGlobal(threadContextBuffer);
            }

            // Resume the thread

            if (PInvoke.ResumeThread(firstThreadHandle) == -1)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to resume a thread in the remote process");
            }

            firstThreadHandle.Dispose();

            PInvoke.SwitchToThisWindow(_injectionWrapper.RemoteProcess.Process.MainWindowHandle, true);

            while (!_injectionWrapper.RemoteProcess.Modules.Any(module => module.FilePath.Equals(_injectionWrapper.DllPath, StringComparison.OrdinalIgnoreCase)))
            {
                _injectionWrapper.RemoteProcess.Refresh();
            }

            // Free the buffers allocated in the remote process

            _injectionWrapper.MemoryManager.FreeVirtualMemory(dllPathBuffer);

            _injectionWrapper.MemoryManager.FreeVirtualMemory(unicodeStringBuffer);

            try
            {
                return _injectionWrapper.MemoryManager.ReadVirtualMemory<IntPtr>(moduleHandleBuffer);
            }

            finally
            {
                _injectionWrapper.MemoryManager.FreeVirtualMemory(moduleHandleBuffer);
            }
        }
    }
}