using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;
using Bleak.Native.Enumerations;
using Bleak.Native.PInvoke;
using Bleak.Native.Structures;
using Bleak.RemoteProcess.FunctionCall.Interfaces;
using Bleak.RemoteProcess.Structures;

namespace Bleak.RemoteProcess.FunctionCall.Methods
{
    internal class HijackThread : IFunctionCall
    {
        private readonly Memory _memory;

        private readonly Process _process;

        internal HijackThread(Memory memory, Process process)
        {
            _memory = memory;

            _process = process;
        }

        public void CallFunction(CallDescriptor callDescriptor)
        {
            var completionFlagBuffer = _memory.AllocateBlock(IntPtr.Zero, sizeof(bool), ProtectionType.ReadWrite);

            // Write the shellcode used to perform the function call into a buffer

            var shellcode = AssembleShellcode(callDescriptor, completionFlagBuffer);

            var shellcodeBuffer = _memory.AllocateBlock(IntPtr.Zero, shellcode.Length, ProtectionType.ReadWrite);

            _memory.WriteBlock(shellcodeBuffer, shellcode);

            _memory.ProtectBlock(shellcodeBuffer, shellcode.Length, ProtectionType.ExecuteRead);

            // Open a handle to the first thread

            var firstThreadHandle = Kernel32.OpenThread(AccessMask.SpecificRightsAll | AccessMask.StandardRightsAll, false, _process.Threads[0].Id);

            if (firstThreadHandle.IsInvalid)
            {
                throw new Win32Exception($"Failed to call OpenThread with error code {Marshal.GetLastWin32Error()}");
            }

            if (callDescriptor.IsWow64Call)
            {
                // Suspend the thread

                if (Kernel32.Wow64SuspendThread(firstThreadHandle) == -1)
                {
                    throw new Win32Exception($"Failed to call Wow64SuspendThread with error code {Marshal.GetLastWin32Error()}");
                }

                // Get the context of the thread

                var threadContext = new Wow64Context {ContextFlags = Wow64ContextFlags.Control};

                if (!Kernel32.Wow64GetThreadContext(firstThreadHandle, ref threadContext))
                {
                    throw new Win32Exception($"Failed to call Wow64GetThreadContext with error code {Marshal.GetLastWin32Error()}");
                }

                // Write the original instruction pointer of the thread into the top of its stack

                threadContext.Esp -= sizeof(int);

                _memory.Write((IntPtr) threadContext.Esp, threadContext.Eip);

                // Overwrite the instruction pointer of the thread with the address of the shellcode

                threadContext.Eip = (int) shellcodeBuffer;

                // Update the context of the thread

                if (!Kernel32.Wow64SetThreadContext(firstThreadHandle, ref threadContext))
                {
                    throw new Win32Exception($"Failed to call Wow64SetThreadContext with error code {Marshal.GetLastWin32Error()}");
                }
            }

            else
            {
                // Suspend the thread

                if (Kernel32.SuspendThread(firstThreadHandle) == -1)
                {
                    throw new Win32Exception($"Failed to call SuspendThread with error code {Marshal.GetLastWin32Error()}");
                }

                // Get the context of the thread

                var threadContext = new Context {ContextFlags = ContextFlags.Control};

                var threadContextBuffer = Marshal.AllocHGlobal(Unsafe.SizeOf<Context>());

                Marshal.StructureToPtr(threadContext, threadContextBuffer, false);

                if (!Kernel32.GetThreadContext(firstThreadHandle, threadContextBuffer))
                {
                    throw new Win32Exception($"Failed to call GetThreadContext with error code {Marshal.GetLastWin32Error()}");
                }

                threadContext = Marshal.PtrToStructure<Context>(threadContextBuffer);

                // Write the original instruction pointer of the thread into the top of its stack

                threadContext.Rsp -= sizeof(long);

                _memory.Write((IntPtr) threadContext.Rsp, threadContext.Rip);

                // Overwrite the instruction pointer of the thread with the address of the shellcode

                threadContext.Rip = (long) shellcodeBuffer;

                Marshal.StructureToPtr(threadContext, threadContextBuffer, false);

                // Update the context of the thread

                if (!Kernel32.SetThreadContext(firstThreadHandle, threadContextBuffer))
                {
                    throw new Win32Exception($"Failed to call SetThreadContext with error code {Marshal.GetLastWin32Error()}");
                }

                Marshal.FreeHGlobal(threadContextBuffer);
            }

            // Send a message to the thread to ensure it executes the shellcode

            if (!User32.PostThreadMessage(_process.Threads[0].Id, MessageType.Null, IntPtr.Zero, IntPtr.Zero))
            {
                throw new Win32Exception($"Failed to call PostThreadMessage with error code {Marshal.GetLastWin32Error()}");
            }

            // Resume the thread

            if (Kernel32.ResumeThread(firstThreadHandle) == -1)
            {
                throw new Win32Exception($"Failed to call ResumeThread with error code {Marshal.GetLastWin32Error()}");
            }

            while (!_memory.Read<bool>(completionFlagBuffer))
            {
                Thread.Sleep(1);
            }

            firstThreadHandle.Dispose();

            _memory.FreeBlock(shellcodeBuffer);

            _memory.FreeBlock(completionFlagBuffer);
        }

        private static byte[] AssembleShellcode(CallDescriptor callDescriptor, IntPtr completionFlagBuffer)
        {
            var shellcode = new List<byte>();

            if (callDescriptor.IsWow64Call)
            {
                // pushf

                shellcode.Add(0x9C);

                // pusha

                shellcode.Add(0x60);

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

                // mov BYTE PTR [completionFlagBuffer], 0x01

                shellcode.AddRange(new byte[] {0xC6, 0x05});

                shellcode.AddRange(BitConverter.GetBytes((int) completionFlagBuffer));

                shellcode.Add(0x01);

                // popa

                shellcode.Add(0x61);

                // popf

                shellcode.Add(0x9D);

                // ret

                shellcode.Add(0xC3);
            }

            else
            {
                // pushf

                shellcode.Add(0x9C);

                // push rax

                shellcode.Add(0x50);

                // push rbx

                shellcode.Add(0x53);

                // push rcx

                shellcode.Add(0x51);

                // push rdx

                shellcode.Add(0x52);

                // push r8

                shellcode.AddRange(new byte[] {0x41, 0x50});

                // push r9

                shellcode.AddRange(new byte[] {0x41, 0x51});

                // push r10

                shellcode.AddRange(new byte[] {0x41, 0x52});

                // push r11

                shellcode.AddRange(new byte[] {0x41, 0x53});

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

                // mov rax, completionFlagBuffer

                shellcode.AddRange(new byte[] {0x48, 0xB8});

                shellcode.AddRange(BitConverter.GetBytes((long) completionFlagBuffer));

                // mov BYTE PTR [rax], 0x01

                shellcode.AddRange(new byte[] {0xC6, 0x00, 0x01});

                // pop r11

                shellcode.AddRange(new byte[] {0x41, 0x5B});

                // pop r10

                shellcode.AddRange(new byte[] {0x41, 0x5A});

                // pop r9

                shellcode.AddRange(new byte[] {0x41, 0x59});

                // pop r8

                shellcode.AddRange(new byte[] {0x41, 0x58});

                // pop rdx

                shellcode.Add(0x5A);

                // pop rcx

                shellcode.Add(0x59);

                // pop rbx

                shellcode.Add(0x5B);

                // pop rax

                shellcode.Add(0x58);

                // popf

                shellcode.Add(0x9D);

                // ret

                shellcode.Add(0xC3);
            }

            return shellcode.ToArray();
        }
    }
}