using System;
using System.Runtime.InteropServices;
using Bleak.Tests.Exceptions;
using Bleak.Tests.Native.PInvoke;
using Microsoft.Win32.SafeHandles;

namespace Bleak.Tests.Memory
{
    internal static class MemoryManager
    {
        internal static byte[] ReadVirtualMemory(SafeProcessHandle processHandle, IntPtr baseAddress, int bytesToRead)
        {
            var bytesBuffer = Marshal.AllocHGlobal(bytesToRead);

            if (!Kernel32.ReadProcessMemory(processHandle, baseAddress, bytesBuffer, bytesToRead, IntPtr.Zero))
            {
                throw new PInvokeException("Failed to call ReadProcessMemory");
            }

            var bytesRead = new byte[bytesToRead];

            Marshal.Copy(bytesBuffer, bytesRead, 0, bytesToRead);

            Marshal.FreeHGlobal(bytesBuffer);

            return bytesRead;
        }
    }
}