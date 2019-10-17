using System;
using System.Collections.Generic;
using System.Linq;
using Bleak.RemoteProcess.Structures;

namespace Bleak.RemoteProcess.FunctionCall
{
    internal static class ParameterAssembler
    {
        internal static void AssembleFastCallParameters(CallDescriptor callDescriptor, ref List<byte> shellcode)
        {
            var stackParameters = new List<byte>();

            var parameterIndex = 0;

            if (callDescriptor.IsWow64Call)
            {
                foreach (var parameter in callDescriptor.Parameters)
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
                foreach (var parameter in callDescriptor.Parameters)
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
        }

        internal static void AssembleStdCallParameters(CallDescriptor callDescriptor, ref List<byte> shellcode)
        {
            foreach (var parameter in callDescriptor.Parameters.Select(p => p).Reverse())
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
        }
    }
}