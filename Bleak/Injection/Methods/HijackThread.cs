using System;
using System.Runtime.InteropServices;
using System.Text;
using Bleak.Assembly.Objects;
using Bleak.Injection.Interfaces;
using Bleak.Injection.Objects;
using Bleak.Native;
using Bleak.Native.Enumerations;
using Bleak.Native.PInvoke;
using Bleak.Native.Structures;
using Bleak.PortableExecutable;
using Bleak.RemoteProcess;
using Bleak.Shared.Exceptions;

namespace Bleak.Injection.Methods
{
    internal class HijackThread : IInjectionMethod
    {
        private readonly string _dllPath;

        private readonly InjectionFlags _injectionFlags;
        
        private readonly PeImage _peImage;

        private readonly ManagedProcess _process;
        
        internal HijackThread(InjectionWrapper injectionWrapper)
        {
            _dllPath = injectionWrapper.DllPath;

            _injectionFlags = injectionWrapper.InjectionFlags;

            _peImage = injectionWrapper.PeImage;

            _process = injectionWrapper.Process;
        }
        
        public void Dispose()
        {
            _peImage.Dispose();
            
            _process.Dispose();
        }

        public IntPtr Call()
        {
            // Write the DLL path into the remote process

            var dllPathAddress = _process.MemoryManager.AllocateVirtualMemory(_dllPath.Length, MemoryProtectionType.ReadWrite);
            
            _process.MemoryManager.WriteVirtualMemory(dllPathAddress, Encoding.Unicode.GetBytes(_dllPath));
            
            // Write a UnicodeString representing the DLL path into the remote process

            IntPtr dllPathUnicodeStringAddress;

            if (_process.IsWow64)
            {
                var dllPathUnicodeString = new UnicodeString32(_dllPath, dllPathAddress);

                dllPathUnicodeStringAddress = _process.MemoryManager.AllocateVirtualMemory(Marshal.SizeOf<UnicodeString32>(), MemoryProtectionType.ReadWrite);
                
                _process.MemoryManager.WriteVirtualMemory(dllPathUnicodeStringAddress, dllPathUnicodeString);
            }

            else
            {
                var dllPathUnicodeString = new UnicodeString64(_dllPath, dllPathAddress);

                dllPathUnicodeStringAddress = _process.MemoryManager.AllocateVirtualMemory(Marshal.SizeOf<UnicodeString64>(), MemoryProtectionType.ReadWrite);
                
                _process.MemoryManager.WriteVirtualMemory(dllPathUnicodeStringAddress, dllPathUnicodeString);
            }
            
            // Write the shellcode used to call LdrLoadDll into the remote process
            
            var ldrLoadDllAddress = _process.GetFunctionAddress("ntdll.dll", "LdrLoadDll");
            
            var moduleHandleAddress = _process.MemoryManager.AllocateVirtualMemory(IntPtr.Size, MemoryProtectionType.ReadWrite);

            var shellcodeReturnAddress = _process.MemoryManager.AllocateVirtualMemory(sizeof(int), MemoryProtectionType.ReadWrite);
            
            var shellcode = _process.Assembler.AssembleThreadFunctionCall(new FunctionCall(ldrLoadDllAddress, CallingConvention.StdCall, new[] {0, 0, (long) dllPathUnicodeStringAddress, (long) moduleHandleAddress}, shellcodeReturnAddress));
            
            var shellcodeAddress = _process.MemoryManager.AllocateVirtualMemory(shellcode.Length, MemoryProtectionType.ReadWrite);
            
            _process.MemoryManager.WriteVirtualMemory(shellcodeAddress, shellcode);
            
            _process.MemoryManager.ProtectVirtualMemory(shellcodeAddress, shellcode.Length, MemoryProtectionType.ExecuteRead);
            
            // Open a handle to the first thread in the remote process
            
            var firstThreadHandle = Kernel32.OpenThread(Constants.ThreadAllAccess, false, _process.Process.Threads[0].Id);

            if (firstThreadHandle is null)
            {
                throw new PInvokeException("Failed to call OpenThread");
            }

            if (_process.IsWow64)
            {
                // Suspend the thread

                if (Kernel32.Wow64SuspendThread(firstThreadHandle) == -1)
                {
                    throw new PInvokeException("Failed to call Wow64SuspendThread");
                }
                
                // Get the context of the thread
                
                var threadContext = new Context32 {ContextFlags = ContextFlags.Integer};
                
                var threadContextBuffer = Marshal.AllocHGlobal(Marshal.SizeOf<Context32>());
                
                Marshal.StructureToPtr(threadContext, threadContextBuffer, false);

                if (!Kernel32.Wow64GetThreadContext(firstThreadHandle, threadContextBuffer))
                {
                    throw new PInvokeException("Failed to call Wow64GetThreadContext");
                }

                threadContext = Marshal.PtrToStructure<Context32>(threadContextBuffer);
                
                // Write the original instruction pointer of the thread into the top of its stack
                
                threadContext.Esp -= sizeof(int);
                
                _process.MemoryManager.WriteVirtualMemory((IntPtr) threadContext.Esp, threadContext.Eip);
                
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
                
                _process.MemoryManager.WriteVirtualMemory((IntPtr) threadContext.Rsp, threadContext.Rip);
                
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
            
            User32.PostThreadMessage(_process.Process.Threads[0].Id, MessageType.Null, IntPtr.Zero, IntPtr.Zero);
            
            // Resume the thread

            if (Kernel32.ResumeThread(firstThreadHandle) == -1)
            {
                throw new PInvokeException("Failed to call ResumeThread");
            }
            
            firstThreadHandle.Dispose();
            
            var shellcodeReturn = _process.MemoryManager.ReadVirtualMemory<int>(shellcodeReturnAddress);

            if ((NtStatus) shellcodeReturn != NtStatus.Success)
            {
                throw new RemoteFunctionCallException("Failed to call LdrLoadDll", (NtStatus) shellcodeReturn);
            }
            
            // Ensure the DLL is loaded before freeing any memory
            
            while (_process.Modules.TrueForAll(module => module.FilePath != _dllPath))
            {
                _process.Refresh();
            }
            
            _process.MemoryManager.FreeVirtualMemory(dllPathAddress);

            _process.MemoryManager.FreeVirtualMemory(dllPathUnicodeStringAddress);
            
            _process.MemoryManager.FreeVirtualMemory(shellcodeReturnAddress);
            
            // Read the address of the DLL that was loaded in the remote process
            
            var remoteDllAddress = _process.MemoryManager.ReadVirtualMemory<IntPtr>(moduleHandleAddress);

            _process.MemoryManager.FreeVirtualMemory(moduleHandleAddress);

            if (!_injectionFlags.HasFlag(InjectionFlags.RandomiseDllHeaders))
            {
                return remoteDllAddress;
            }
            
            // Write over the header region of the DLL with random bytes
                
            var randomBuffer = new byte[_peImage.PeHeaders.PEHeader.SizeOfHeaders];

            new Random().NextBytes(randomBuffer);

            _process.MemoryManager.WriteVirtualMemory(remoteDllAddress, randomBuffer);

            return remoteDllAddress;
        }
    }
}