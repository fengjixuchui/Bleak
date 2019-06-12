using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace Bleak.Assembly
{
    internal class Assembler
    {
        private readonly bool _isWow64;

        internal Assembler(bool isWow64)
        {
            _isWow64 = isWow64;
        }

        internal byte[] AssembleFunctionCall(CallingConvention callingConvention, IntPtr functionAddress, IntPtr returnAddress, ulong[] parameters)
        {
            var shellcode = new List<byte>();

            if (_isWow64)
            {
                // Assemble parameters
                
                shellcode.AddRange(callingConvention == CallingConvention.StdCall ? AssembleStdCallParameters(parameters) : AssembleFastCallParameters(parameters));
                
                // mov eax, functionAddress
            
                shellcode.Add(0xB8);
                
                shellcode.AddRange(BitConverter.GetBytes((uint) functionAddress));
                
                // call eax
                
                shellcode.AddRange(new byte[] {0xFF, 0xD0});

                if (returnAddress != IntPtr.Zero)
                {
                    // mov [returnAddress], eax
                    
                    shellcode.Add(0xA3);
                    
                    shellcode.AddRange(BitConverter.GetBytes((uint) returnAddress));
                }
                
                // xor eax, eax
                
                shellcode.AddRange(new byte[] {0x33, 0xC0});
            }

            else
            {
                // sub rsp, 0x28

                shellcode.AddRange(new byte[] {0x48, 0x83, 0xEC, 0x28});
                
                // Assemble parameters
                
                shellcode.AddRange(callingConvention == CallingConvention.StdCall ? AssembleStdCallParameters(parameters) : AssembleFastCallParameters(parameters));
                
                // mov rax, functionAddress
                
                shellcode.AddRange(new byte[] {0x48, 0xB8});

                shellcode.AddRange(BitConverter.GetBytes((ulong) functionAddress));
                
                // call rax

                shellcode.AddRange(new byte[] {0xFF, 0xD0});
                
                if (returnAddress != IntPtr.Zero)
                {
                    // mov [returnAddress], rax
                    
                    shellcode.AddRange(new byte[] {0x48, 0xA3});

                    shellcode.AddRange(BitConverter.GetBytes((ulong) returnAddress));
                }
                
                // xor eax, eax
                
                shellcode.AddRange(new byte[] {0x31, 0xC0});
                
                // add rsp, 0x28
                
                shellcode.AddRange(new byte[] {0x48, 0x83, 0xC4, 0x28});
            }
            
            // ret
                
            shellcode.Add(0xC3);

            return shellcode.ToArray();
        }
        
        internal byte[] AssembleThreadFunctionCall(CallingConvention callingConvention, IntPtr functionAddress, IntPtr returnAddress, params ulong[] parameters)
        {
            var shellcode = new List<byte>();

            if (_isWow64)
            {
                // pushf

                shellcode.Add(0x9C);

                // pusha

                shellcode.Add(0x60);
                
                // Assemble parameters
                
                shellcode.AddRange(callingConvention == CallingConvention.StdCall ? AssembleStdCallParameters(parameters) : AssembleFastCallParameters(parameters));
                
                // mov eax, functionAddress
            
                shellcode.Add(0xB8);
                
                shellcode.AddRange(BitConverter.GetBytes((uint) functionAddress));
                
                // call eax
                
                shellcode.AddRange(new byte[] {0xFF, 0xD0});

                if (returnAddress != IntPtr.Zero)
                {
                    // mov [returnAddress], eax
                    
                    shellcode.Add(0xA3);
                    
                    shellcode.AddRange(BitConverter.GetBytes((uint) returnAddress));
                }
                
                // popa

                shellcode.Add(0x61);

                // popf

                shellcode.Add(0x9D);
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
                
                // sub rsp, 0x28

                shellcode.AddRange(new byte[] {0x48, 0x83, 0xEC, 0x28});
                
                // Assemble parameters
                
                shellcode.AddRange(callingConvention == CallingConvention.StdCall ? AssembleStdCallParameters(parameters) : AssembleFastCallParameters(parameters));
                
                // mov rax, functionAddress
                
                shellcode.AddRange(new byte[] {0x48, 0xB8});

                shellcode.AddRange(BitConverter.GetBytes((ulong) functionAddress));
                
                // call rax

                shellcode.AddRange(new byte[] {0xFF, 0xD0});
                
                if (returnAddress != IntPtr.Zero)
                {
                    // mov [returnAddress], rax
                    
                    shellcode.AddRange(new byte[] {0x48, 0xA3});

                    shellcode.AddRange(BitConverter.GetBytes((ulong) returnAddress));
                }
                
                // add rsp, 0x28
                
                shellcode.AddRange(new byte[] {0x48, 0x83, 0xC4, 0x28});
                
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
            }
            
            // ret
                
            shellcode.Add(0xC3);

            return shellcode.ToArray();
        }

        private byte[] AssembleFastCallParameters(ulong[] parameters)
        {
            var shellcode = new List<byte>();
            
            if (_isWow64)
            {
                var stackParameters = new List<byte>();
                
                for (var parameterIndex = 0; parameterIndex < parameters.Length; parameterIndex += 1)
                {
                    switch (parameterIndex)
                    {
                        case 0:
                        {
                            if (parameters[parameterIndex] == 0)
                            {
                                // xor ecx, ecx
                                
                                shellcode.AddRange(new byte[] {0x31, 0xC9});
                            }

                            else
                            {
                                // mov ecx, parameter
                                
                                shellcode.Add(0xB9);
                                
                                shellcode.AddRange(BitConverter.GetBytes((uint) parameters[parameterIndex]));
                            }
                            
                            break;
                        }

                        case 1:
                        {
                            if (parameters[parameterIndex] == 0)
                            {
                                // xor edx, edx
                                
                                shellcode.AddRange(new byte[] {0x31, 0xD2});
                            }

                            else
                            {
                                // mov edx, parameter
                                
                                shellcode.Add(0xBA);
                                
                                shellcode.AddRange(BitConverter.GetBytes((uint) parameters[parameterIndex]));
                            }
                            
                            break;
                        }

                        default:
                        {
                            if (parameters[parameterIndex] <= 0x7F)
                            {
                                // push parameter
                                
                                stackParameters.InsertRange(0, new byte[] {0x6A, (byte) parameters[parameterIndex]});
                            }

                            else
                            {
                                // push parameter
                                
                                var operation = new List<byte> {0x68};

                                operation.AddRange(BitConverter.GetBytes((uint) parameters[parameterIndex]));
                                
                                stackParameters.InsertRange(0, operation);
                            }

                            break;
                        }
                    }
                }
                
                // push parameters
                
                shellcode.AddRange(stackParameters);
            }

            else
            {
                for (var parameterIndex = 0; parameterIndex < parameters.Length; parameterIndex += 1)
                {
                    switch (parameterIndex)
                    {
                        case 0:
                        {
                            if (parameters[parameterIndex] == 0)
                            {
                                // xor ecx, ecx
                                
                                shellcode.AddRange(new byte[] {0x31, 0xC9});
                            }

                            else
                            {
                                // mov rcx, parameter
                                
                                shellcode.AddRange(new byte[] {0x48, 0xB9});
                                
                                shellcode.AddRange(BitConverter.GetBytes(parameters[parameterIndex]));
                            }
                            
                            break;
                        }

                        case 1:
                        {
                            if (parameters[parameterIndex] == 0)
                            {
                                // xor edx, edx
                                
                                shellcode.AddRange(new byte[] {0x31, 0xD2});
                            }

                            else
                            {
                                // mov rdx, parameter
                                
                                shellcode.AddRange(new byte[] {0x48, 0xBA});
                                
                                shellcode.AddRange(BitConverter.GetBytes(parameters[parameterIndex]));
                            }
                            
                            break;
                        }

                        case 2:
                        {
                            if (parameters[parameterIndex] == 0)
                            {
                                // xor r8, r8
                                
                                shellcode.AddRange(new byte[] {0x4D, 0x31, 0xC0});
                            }

                            else
                            {
                                // mov r8, parameter
                                
                                shellcode.AddRange(new byte[] {0x49, 0xB8});
                                
                                shellcode.AddRange(BitConverter.GetBytes(parameters[parameterIndex]));
                            }
                            
                            break;
                        }

                        case 3:
                        {
                            if (parameters[parameterIndex] == 0)
                            {
                                // xor r9, r9
                                
                                shellcode.AddRange(new byte[] {0x4D, 0x31, 0xC9});
                            }

                            else
                            {
                                // mov r9, parameter
                                
                                shellcode.AddRange(new byte[] {0x49, 0xB9});
                                
                                shellcode.AddRange(BitConverter.GetBytes(parameters[parameterIndex]));
                            }
                            
                            break;
                        }
                    }
                }
            }
            
            return shellcode.ToArray();
        }
        
        private byte[] AssembleStdCallParameters(ulong[] parameters)
        {
            var shellcode = new List<byte>();

            if (_isWow64)
            {
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
                    
                        shellcode.AddRange(BitConverter.GetBytes((uint) parameter));
                    }
                }
            }

            else
            {
                return AssembleFastCallParameters(parameters);
            }

            return shellcode.ToArray();
        }
    }
}