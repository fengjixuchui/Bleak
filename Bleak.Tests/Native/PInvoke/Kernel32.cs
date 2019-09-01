using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Bleak.Tests.Native.PInvoke
{
    internal static class Kernel32
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool ReadProcessMemory(SafeProcessHandle processHandle, IntPtr baseAddress, IntPtr bytesRead, int bytesToRead, IntPtr numberOfBytesRead);

    }
}