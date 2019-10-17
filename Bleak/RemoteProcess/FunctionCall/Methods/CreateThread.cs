using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Bleak.Native.Enumerations;
using Bleak.Native.PInvoke;
using Bleak.Native.Structures;
using Bleak.RemoteProcess.FunctionCall.Interfaces;
using Bleak.RemoteProcess.Structures;

namespace Bleak.RemoteProcess.FunctionCall.Methods
{
    internal class CreateThread : IFunctionCall
    {
        private readonly Memory _memory;

        private readonly Process _process;

        internal CreateThread(Memory memory, Process process)
        {
            _memory = memory;

            _process = process;
        }

        public void CallFunction(CallDescriptor callDescriptor)
        {
            // Write the shellcode used to perform the function call into a buffer

            var shellcode = AssembleShellcode(callDescriptor);

            var shellcodeBuffer = _memory.AllocateBlock(IntPtr.Zero, shellcode.Length, ProtectionType.ReadWrite);

            _memory.WriteBlock(shellcodeBuffer, shellcode);

            _memory.ProtectBlock(shellcodeBuffer, shellcode.Length, ProtectionType.ExecuteRead);

            // Create a suspended thread with a spoofed start address

            var ntStatus = Ntdll.NtCreateThreadEx(out var threadHandle, AccessMask.SpecificRightsAll | AccessMask.StandardRightsAll, IntPtr.Zero, _process.SafeHandle, _process.MainModule.BaseAddress, IntPtr.Zero, ThreadCreationFlags.CreateSuspended | ThreadCreationFlags.HideFromDebugger, 0, 0, 0, IntPtr.Zero);

            if (ntStatus != NtStatus.Success)
            {
                throw new Win32Exception($"Failed to call NtCreateThreadEx with error code {ntStatus}");
            }

            if (callDescriptor.IsWow64Call)
            {
                // Get the context of the thread

                var threadContext = new Wow64Context {ContextFlags = Wow64ContextFlags.Integer};

                if (!Kernel32.Wow64GetThreadContext(threadHandle, ref threadContext))
                {
                    throw new Win32Exception($"Failed to call Wow64GetThreadContext with error code {Marshal.GetLastWin32Error()}");
                }

                // Change the spoofed start address to the address of the shellcode

                threadContext.Eax = (int) shellcodeBuffer;

                // Update the context of the thread

                if (!Kernel32.Wow64SetThreadContext(threadHandle, ref threadContext))
                {
                    throw new Win32Exception($"Failed to call Wow64GetThreadContext with error code {Marshal.GetLastWin32Error()}");
                }
            }

            else
            {
                // Get the context of the thread

                var threadContext = new Context {ContextFlags = ContextFlags.Integer};

                var threadContextBuffer = Marshal.AllocHGlobal(Unsafe.SizeOf<Context>());

                Marshal.StructureToPtr(threadContext, threadContextBuffer, false);

                if (!Kernel32.GetThreadContext(threadHandle, threadContextBuffer))
                {
                    throw new Win32Exception($"Failed to call GetThreadContext with error code {Marshal.GetLastWin32Error()}");
                }

                threadContext = Marshal.PtrToStructure<Context>(threadContextBuffer);

                // Change the spoofed start address to the address of the shellcode

                threadContext.Rcx = (long) shellcodeBuffer;

                Marshal.StructureToPtr(threadContext, threadContextBuffer, false);

                // Update the context of the thread

                if (!Kernel32.SetThreadContext(threadHandle, threadContextBuffer))
                {
                    throw new Win32Exception($"Failed to call SetThreadContext with error code {Marshal.GetLastWin32Error()}");
                }

                Marshal.FreeHGlobal(threadContextBuffer);
            }

            // Resume the thread

            if (Kernel32.ResumeThread(threadHandle) == -1)
            {
                throw new Win32Exception($"Failed to call ResumeThread with error code {Marshal.GetLastWin32Error()}");
            }

            if (Kernel32.WaitForSingleObject(threadHandle, int.MaxValue) == -1)
            {
                throw new Win32Exception($"Failed to call WaitForSingleObject with error code {Marshal.GetLastWin32Error()}");
            }

            threadHandle.Dispose();

            _memory.FreeBlock(shellcodeBuffer);
        }

        private static byte[] AssembleShellcode(CallDescriptor callDescriptor)
        {
            var shellcode = new List<byte>();

            if (callDescriptor.IsWow64Call)
            {
                // Assemble the function parameters

                if (callDescriptor.CallingConvention == CallingConvention.FastCall)
                {
                    ParameterAssembler.AssembleFastCallParameters(callDescriptor, ref shellcode);
                }

                else
                {
                    ParameterAssembler.AssembleStdCallParameters(callDescriptor, ref shellcode);
                }

                // mov eax, functionAddress

                shellcode.Add(0xB8);

                shellcode.AddRange(BitConverter.GetBytes((int) callDescriptor.FunctionAddress));

                // call eax

                shellcode.AddRange(new byte[] {0xFF, 0xD0});

                if (callDescriptor.ReturnAddress != IntPtr.Zero)
                {
                    // mov [returnAddress], eax

                    shellcode.Add(0xA3);

                    shellcode.AddRange(BitConverter.GetBytes((int) callDescriptor.ReturnAddress));
                }

                // xor eax, eax

                shellcode.AddRange(new byte[] {0x33, 0xC0});

                // ret

                shellcode.Add(0xC3);
            }

            else
            {
                // Assemble the function parameters

                ParameterAssembler.AssembleFastCallParameters(callDescriptor, ref shellcode);

                // mov rax, functionAddress

                shellcode.AddRange(new byte[] {0x48, 0xB8});

                shellcode.AddRange(BitConverter.GetBytes((long) callDescriptor.FunctionAddress));

                // sub rsp, 0x28

                shellcode.AddRange(new byte[] {0x48, 0x83, 0xEC, 0x28});

                // call rax

                shellcode.AddRange(new byte[] {0xFF, 0xD0});

                // add rsp, 0x28

                shellcode.AddRange(new byte[] {0x48, 0x83, 0xC4, 0x28});

                if (callDescriptor.ReturnAddress != IntPtr.Zero)
                {
                    // mov [returnAddress], rax

                    shellcode.AddRange(new byte[] {0x48, 0xA3});

                    shellcode.AddRange(BitConverter.GetBytes((long) callDescriptor.ReturnAddress));
                }

                // xor eax, eax

                shellcode.AddRange(new byte[] {0x31, 0xC0});

                // ret

                shellcode.Add(0xC3);
            }

            return shellcode.ToArray();
        }
    }
}