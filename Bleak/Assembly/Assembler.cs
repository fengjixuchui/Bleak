using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace Bleak.Assembly
{
    internal static class Assembler
    {
        internal static byte[] AssembleFunctionCall(FunctionCall functionCall)
        {
            var shellcode = new List<byte>();

            if (functionCall.IsWow64)
            {
                // Assemble the function parameters

                switch (functionCall.CallingConvention)
                {
                    case CallingConvention.FastCall:
                    {
                        shellcode.AddRange(AssembleFastCallParameters(functionCall.IsWow64, functionCall.Parameters));

                        break;
                    }

                    case CallingConvention.StdCall:
                    {
                        shellcode.AddRange(AssembleStdCallParameters(functionCall.Parameters));

                        break;
                    }
                }

                // mov eax, functionAddress

                shellcode.Add(0xB8);

                shellcode.AddRange(BitConverter.GetBytes((int) functionCall.FunctionAddress));

                // call eax

                shellcode.AddRange(new byte[] {0xFF, 0xD0});

                if (functionCall.ReturnAddress != IntPtr.Zero)
                {
                    // mov [returnAddress], eax

                    shellcode.Add(0xA3);

                    shellcode.AddRange(BitConverter.GetBytes((int) functionCall.ReturnAddress));
                }

                // xor eax, eax

                shellcode.AddRange(new byte[] {0x33, 0xC0});

                // ret

                shellcode.Add(0xC3);
            }

            else
            {
                // Assemble the function parameters

                shellcode.AddRange(AssembleFastCallParameters(functionCall.IsWow64, functionCall.Parameters));

                // mov rax, functionAddress

                shellcode.AddRange(new byte[] {0x48, 0xB8});

                shellcode.AddRange(BitConverter.GetBytes((long) functionCall.FunctionAddress));

                // sub rsp, 0x28

                shellcode.AddRange(new byte[] {0x48, 0x83, 0xEC, 0x28});

                // call rax

                shellcode.AddRange(new byte[] {0xFF, 0xD0});

                // add rsp, 0x28

                shellcode.AddRange(new byte[] {0x48, 0x83, 0xC4, 0x28});

                if (functionCall.ReturnAddress != IntPtr.Zero)
                {
                    // mov [returnAddress], rax

                    shellcode.AddRange(new byte[] {0x48, 0xA3});

                    shellcode.AddRange(BitConverter.GetBytes((long) functionCall.ReturnAddress));
                }

                // xor eax, eax

                shellcode.AddRange(new byte[] {0x31, 0xC0});

                // ret

                shellcode.Add(0xC3);
            }

            return shellcode.ToArray();
        }

        internal static byte[] AssembleThreadFunctionCall(FunctionCall functionCall)
        {
            var shellcode = new List<byte>();

            if (functionCall.IsWow64)
            {
                // pushf

                shellcode.Add(0x9C);

                // pusha

                shellcode.Add(0x60);

                // Assemble the function parameters

                switch (functionCall.CallingConvention)
                {
                    case CallingConvention.FastCall:
                    {
                        shellcode.AddRange(AssembleFastCallParameters(functionCall.IsWow64, functionCall.Parameters));

                        break;
                    }

                    case CallingConvention.StdCall:
                    {
                        shellcode.AddRange(AssembleStdCallParameters(functionCall.Parameters));

                        break;
                    }
                }

                // mov eax, functionAddress

                shellcode.Add(0xB8);

                shellcode.AddRange(BitConverter.GetBytes((int) functionCall.FunctionAddress));

                // call eax

                shellcode.AddRange(new byte[] {0xFF, 0xD0});

                if (functionCall.ReturnAddress != IntPtr.Zero)
                {
                    // mov [returnAddress], eax

                    shellcode.Add(0xA3);

                    shellcode.AddRange(BitConverter.GetBytes((int) functionCall.ReturnAddress));
                }

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

                shellcode.AddRange(AssembleFastCallParameters(functionCall.IsWow64, functionCall.Parameters));

                // mov rax, functionAddress

                shellcode.AddRange(new byte[] {0x48, 0xB8});

                shellcode.AddRange(BitConverter.GetBytes((long) functionCall.FunctionAddress));

                // sub rsp, 0x28

                shellcode.AddRange(new byte[] {0x48, 0x83, 0xEC, 0x28});

                // call rax

                shellcode.AddRange(new byte[] {0xFF, 0xD0});

                // add rsp, 0x28

                shellcode.AddRange(new byte[] {0x48, 0x83, 0xC4, 0x28});

                if (functionCall.ReturnAddress != IntPtr.Zero)
                {
                    // mov [returnAddress], rax

                    shellcode.AddRange(new byte[] {0x48, 0xA3});

                    shellcode.AddRange(BitConverter.GetBytes((long) functionCall.ReturnAddress));
                }

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

        private static List<byte> AssembleFastCallParameters(bool isWow64, long[] parameters)
        {
            var shellcode = new List<byte>();

            var stackParameters = new List<byte>();

            var parameterIndex = 0;

            if (isWow64)
            {
                foreach (var parameter in parameters)
                {
                    switch (parameterIndex)
                    {
                        case 0:
                        {
                            if (parameter == 0)
                            {
                                // xor ecx, ecx

                                shellcode.AddRange(new byte[] {0x31, 0xC9});
                            }

                            else
                            {
                                // mov ecx, parameter

                                shellcode.Add(0xB9);

                                shellcode.AddRange(BitConverter.GetBytes((int) parameter));
                            }

                            parameterIndex += 1;

                            break;
                        }

                        case 1:
                        {
                            if (parameter == 0)
                            {
                                // xor edx, edx

                                shellcode.AddRange(new byte[] {0x31, 0xD2});
                            }

                            else
                            {
                                // mov edx, parameter

                                shellcode.Add(0xBA);

                                shellcode.AddRange(BitConverter.GetBytes((int) parameter));
                            }

                            parameterIndex += 1;

                            break;
                        }

                        default:
                        {
                            if (parameter <= 0x7F)
                            {
                                // push parameter

                                stackParameters.InsertRange(0, new byte[] {0x6A, (byte) parameter});
                            }

                            else
                            {
                                // push parameter

                                var operation = new List<byte> {0x68};

                                operation.AddRange(BitConverter.GetBytes((int) parameter));

                                stackParameters.InsertRange(0, operation);
                            }

                            break;
                        }
                    }
                }
            }

            else
            {
                foreach (var parameter in parameters)
                {
                    switch (parameterIndex)
                    {
                        case 0:
                        {
                            if (parameter == 0)
                            {
                                // xor ecx, ecx

                                shellcode.AddRange(new byte[] {0x31, 0xC9});
                            }

                            else
                            {
                                // mov rcx, parameter

                                shellcode.AddRange(new byte[] {0x48, 0xB9});

                                shellcode.AddRange(BitConverter.GetBytes(parameter));
                            }

                            parameterIndex += 1;

                            break;
                        }

                        case 1:
                        {
                            if (parameter == 0)
                            {
                                // xor edx, edx

                                shellcode.AddRange(new byte[] {0x31, 0xD2});
                            }

                            else
                            {
                                // mov rdx, parameter

                                shellcode.AddRange(new byte[] {0x48, 0xBA});

                                shellcode.AddRange(BitConverter.GetBytes(parameter));
                            }

                            parameterIndex += 1;

                            break;
                        }

                        case 2:
                        {
                            if (parameter == 0)
                            {
                                // xor r8, r8

                                shellcode.AddRange(new byte[] {0x4D, 0x31, 0xC0});
                            }

                            else
                            {
                                // mov r8, parameter

                                shellcode.AddRange(new byte[] {0x49, 0xB8});

                                shellcode.AddRange(BitConverter.GetBytes(parameter));
                            }

                            parameterIndex += 1;

                            break;
                        }

                        case 3:
                        {
                            if (parameter == 0)
                            {
                                // xor r9, r9

                                shellcode.AddRange(new byte[] {0x4D, 0x31, 0xC9});
                            }

                            else
                            {
                                // mov r9, parameter

                                shellcode.AddRange(new byte[] {0x49, 0xB9});

                                shellcode.AddRange(BitConverter.GetBytes(parameter));
                            }

                            parameterIndex += 1;

                            break;
                        }

                        default:
                        {
                            if (parameter <= 0x7F)
                            {
                                // push parameter

                                stackParameters.InsertRange(0, new byte[] {0x6A, (byte) parameter});
                            }

                            else
                            {
                                var operation = new List<byte>();

                                if (parameter < int.MaxValue)
                                {
                                    // push parameter

                                    operation.Add(0x68);

                                    operation.AddRange(BitConverter.GetBytes((int) parameter));
                                }

                                else
                                {
                                    // mov rax, parameter

                                    operation.AddRange(new byte[] {0x48, 0xB8});

                                    operation.AddRange(BitConverter.GetBytes(parameter));

                                    // push rax

                                    operation.Add(0x50);
                                }

                                stackParameters.InsertRange(0, operation);
                            }

                            break;
                        }
                    }
                }
            }

            shellcode.AddRange(stackParameters);

            return shellcode;
        }

        private static List<byte> AssembleStdCallParameters(long[] parameters)
        {
            var shellcode = new List<byte>();

            foreach (var parameter in parameters.Select(p => p).Reverse())
            {
                if (parameter <= 0x7F)
                {
                    // push parameter

                    shellcode.AddRange(new byte[] {0x6A, (byte) parameter});
                }

                else
                {
                    // push parameter

                    shellcode.Add(0x68);

                    shellcode.AddRange(BitConverter.GetBytes((int) parameter));
                }
            }

            return shellcode;
        }
    }
}