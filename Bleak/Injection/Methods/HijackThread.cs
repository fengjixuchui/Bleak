using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Bleak.Assembly;
using Bleak.Exceptions;
using Bleak.Native;
using Bleak.Native.Enumerations;
using Bleak.Native.PInvoke;
using Bleak.Native.Structures;
using Bleak.Memory;

namespace Bleak.Injection.Methods
{
    internal class HijackThread : InjectionBase
    {
        public HijackThread(string dllPath, Process process, InjectionFlags injectionFlags) : base(dllPath, process, injectionFlags) { }

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

            // Write the shellcode used to call LdrLoadDll into the remote process

            var ldrLoadDllAddress = ProcessManager.GetFunctionAddress("ntdll.dll", "LdrLoadDll");

            var moduleHandleAddress = MemoryManager.AllocateVirtualMemory(ProcessManager.Process.SafeHandle, IntPtr.Zero, IntPtr.Size, MemoryProtectionType.ReadWrite);

            var shellcodeReturnAddress = MemoryManager.AllocateVirtualMemory(ProcessManager.Process.SafeHandle, IntPtr.Zero, sizeof(int), MemoryProtectionType.ReadWrite);

            var shellcode = Assembler.AssembleThreadFunctionCall(new FunctionCall(ProcessManager.IsWow64, ldrLoadDllAddress, CallingConvention.StdCall, new[] {0, 0, (long) dllPathUnicodeStringAddress, (long) moduleHandleAddress}, shellcodeReturnAddress));

            var shellcodeAddress = MemoryManager.AllocateVirtualMemory(ProcessManager.Process.SafeHandle, IntPtr.Zero, shellcode.Length, MemoryProtectionType.ReadWrite);

            MemoryManager.WriteVirtualMemory(ProcessManager.Process.SafeHandle, shellcodeAddress, shellcode);

            MemoryManager.ProtectVirtualMemory(ProcessManager.Process.SafeHandle, shellcodeAddress, shellcode.Length, MemoryProtectionType.ExecuteRead);

            // Open a handle to the first thread in the remote process

            var firstThreadHandle = Kernel32.OpenThread(Constants.ThreadAllAccess, false, ProcessManager.Process.Threads[0].Id);

            if (firstThreadHandle is null)
            {
                throw new PInvokeException("Failed to call OpenThread");
            }

            if (ProcessManager.IsWow64)
            {
                // Suspend the thread

                if (Kernel32.Wow64SuspendThread(firstThreadHandle) == -1)
                {
                    throw new PInvokeException("Failed to call Wow64SuspendThread");
                }

                // Get the context of the thread

                var threadContext = new Context32 {ContextFlags = ContextFlags.Control};

                var threadContextBuffer = Marshal.AllocHGlobal(Marshal.SizeOf<Context32>());

                Marshal.StructureToPtr(threadContext, threadContextBuffer, false);

                if (!Kernel32.Wow64GetThreadContext(firstThreadHandle, threadContextBuffer))
                {
                    throw new PInvokeException("Failed to call Wow64GetThreadContext");
                }

                threadContext = Marshal.PtrToStructure<Context32>(threadContextBuffer);

                // Write the original instruction pointer of the thread into the top of its stack

                threadContext.Esp -= sizeof(int);

                MemoryManager.WriteVirtualMemory(ProcessManager.Process.SafeHandle, (IntPtr) threadContext.Esp, threadContext.Eip);

                // Overwrite the instruction pointer of the thread with the address of the shellcode

                threadContext.Eip = (int) shellcodeAddress;

                Marshal.StructureToPtr(threadContext, threadContextBuffer, false);

                // Update the context of the thread

                if (!Kernel32.Wow64SetThreadContext(firstThreadHandle, threadContextBuffer))
                {
                    throw new PInvokeException("Failed to call Wow64SetThreadContext");
                }

                Marshal.FreeHGlobal(threadContextBuffer);
            }

            else
            {
                // Suspend the thread

                if (Kernel32.SuspendThread(firstThreadHandle) == -1)
                {
                    throw new PInvokeException("Failed to call SuspendThread");
                }

                // Get the context of the thread

                var threadContext = new Context64 {ContextFlags = ContextFlags.Control};

                var threadContextBuffer = Marshal.AllocHGlobal(Marshal.SizeOf<Context64>());

                Marshal.StructureToPtr(threadContext, threadContextBuffer, false);

                if (!Kernel32.GetThreadContext(firstThreadHandle, threadContextBuffer))
                {
                    throw new PInvokeException("Failed to call GetThreadContext");
                }

                threadContext = Marshal.PtrToStructure<Context64>(threadContextBuffer);

                // Write the original instruction pointer of the thread into the top of its stack

                threadContext.Rsp -= sizeof(long);

                MemoryManager.WriteVirtualMemory(ProcessManager.Process.SafeHandle, (IntPtr) threadContext.Rsp, threadContext.Rip);

                // Overwrite the instruction pointer of the thread with the address of the shellcode

                threadContext.Rip = (long) shellcodeAddress;

                Marshal.StructureToPtr(threadContext, threadContextBuffer, false);

                // Update the context of the thread

                if (!Kernel32.SetThreadContext(firstThreadHandle, threadContextBuffer))
                {
                    throw new PInvokeException("Failed to call SetThreadContext");
                }

                Marshal.FreeHGlobal(threadContextBuffer);
            }

            // Send a message to the thread to ensure it executes the shellcode

            User32.PostThreadMessage(ProcessManager.Process.Threads[0].Id, MessageType.Null, IntPtr.Zero, IntPtr.Zero);

            // Resume the thread

            if (Kernel32.ResumeThread(firstThreadHandle) == -1)
            {
                throw new PInvokeException("Failed to call ResumeThread");
            }

            firstThreadHandle.Dispose();

            var shellcodeReturn = MemoryManager.ReadVirtualMemory<int>(ProcessManager.Process.SafeHandle, shellcodeReturnAddress);

            if ((NtStatus) shellcodeReturn != NtStatus.Success)
            {
                throw new RemoteFunctionCallException("Failed to call LdrLoadDll", (NtStatus) shellcodeReturn);
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

            MemoryManager.FreeVirtualMemory(ProcessManager.Process.SafeHandle, shellcodeReturnAddress);

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