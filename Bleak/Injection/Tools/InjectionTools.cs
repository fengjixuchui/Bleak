using System;
using Bleak.Handlers;
using Bleak.Injection.Objects;
using Bleak.Native;
using Bleak.Native.SafeHandle;

namespace Bleak.Injection.Tools
{
    internal class InjectionTools
    {
        private readonly InjectionWrapper _injectionWrapper;
        
        internal InjectionTools(InjectionWrapper injectionWrapper)
        {
            _injectionWrapper = injectionWrapper;
        }
        
        internal void CallRemoteFunction(IntPtr functionAddress, params ulong[] parameters)
        {
            // Write the shellcode used to call the function into the remote process

            var shellcode = _injectionWrapper.Assembler.AssembleFunctionCall(functionAddress, parameters);

            var shellcodeBuffer = _injectionWrapper.MemoryManager.AllocateVirtualMemory(shellcode.Length);

            _injectionWrapper.MemoryManager.WriteVirtualMemory(shellcodeBuffer, shellcode);

            // Create a thread to call the shellcode in the remote process

            SafeThreadHandle remoteThreadHandle;

            if (IsWindows7())
            {
                if (PInvoke.NtCreateThreadEx(out remoteThreadHandle, Enumerations.ThreadAccessMask.AllAccess,IntPtr.Zero, _injectionWrapper.RemoteProcess.Process.SafeHandle, shellcodeBuffer, IntPtr.Zero, Enumerations.ThreadCreationType.HideFromDebugger, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero) != Enumerations.NtStatus.Success)
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to create a thread in the remote process");
                }
            }

            else
            {
                if (PInvoke.RtlCreateUserThread(_injectionWrapper.RemoteProcess.Process.SafeHandle, IntPtr.Zero, false, 0, IntPtr.Zero, IntPtr.Zero, shellcodeBuffer, IntPtr.Zero, out remoteThreadHandle, out _) != Enumerations.NtStatus.Success)
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to create a thread in the remote process");
                }
            }

            PInvoke.WaitForSingleObject(remoteThreadHandle, int.MaxValue);

            remoteThreadHandle.Dispose();

            _injectionWrapper.MemoryManager.FreeVirtualMemory(shellcodeBuffer);
        }
        
        internal void CallRemoteFunction(string moduleName, string functionName, params ulong[] parameters)
        {
            // Get the address of the function in the remote process

            var functionAddress = _injectionWrapper.RemoteProcess.GetFunctionAddress(moduleName, functionName);

            // Call the function in the remote process

            CallRemoteFunction(functionAddress, parameters);
        }

        internal IntPtr CreateRemoteUnicodeString(IntPtr stringBuffer)
        {
            IntPtr unicodeStringBuffer;
            
            if (_injectionWrapper.RemoteProcess.IsWow64)
            {
                var unicodeString = new Structures.UnicodeString32(_injectionWrapper.DllPath)
                {
                    Buffer = (uint) stringBuffer
                };

                unicodeStringBuffer = _injectionWrapper.MemoryManager.AllocateVirtualMemory<Structures.UnicodeString32>();

                _injectionWrapper.MemoryManager.WriteVirtualMemory(unicodeStringBuffer, unicodeString);
            }

            else
            {
                var unicodeString = new Structures.UnicodeString64(_injectionWrapper.DllPath)
                {
                    Buffer = (ulong) stringBuffer
                };

                unicodeStringBuffer = _injectionWrapper.MemoryManager.AllocateVirtualMemory<Structures.UnicodeString64>();

                _injectionWrapper.MemoryManager.WriteVirtualMemory(unicodeStringBuffer, unicodeString);
            }
            
            return unicodeStringBuffer;
        }
        
        private static bool IsWindows7()
        {
            if (PInvoke.RtlGetVersion(out var versionInformation) != Enumerations.NtStatus.Success)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to determine the version of Windows");
            }

            return versionInformation.MajorVersion == 6 && versionInformation.MinorVersion == 1;
        }
    }
}