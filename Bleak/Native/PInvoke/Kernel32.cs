using System;
using System.Runtime.InteropServices;
using Bleak.Native.Enumerations;
using Bleak.Native.SafeHandle;
using Bleak.Native.Structures;
using Microsoft.Win32.SafeHandles;

namespace Bleak.Native.PInvoke
{
    internal static class Kernel32
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool GetThreadContext(SafeThreadHandle threadHandle, IntPtr context);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool IsWow64Process(SafeProcessHandle processHandle, out bool isWow64Process);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern SafeThreadHandle OpenThread(AccessMask accessMask, bool inheritHandle, int threadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool ReadProcessMemory(SafeProcessHandle processHandle, IntPtr baseAddress, ref byte buffer, int bufferSize, out int numberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern int ResumeThread(SafeThreadHandle threadHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool SetThreadContext(SafeThreadHandle threadHandle, IntPtr context);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern int SuspendThread(SafeThreadHandle threadHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr VirtualAllocEx(SafeProcessHandle processHandle, IntPtr baseAddress, int allocationSize, AllocationType allocationType, ProtectionType protectionType);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool VirtualFreeEx(SafeProcessHandle processHandle, IntPtr baseAddress, int freeSize, FreeType freeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool VirtualProtectEx(SafeProcessHandle processHandle, IntPtr baseAddress, int protectionSize, ProtectionType protectionType, out ProtectionType oldProtectionType);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern int WaitForSingleObject(SafeThreadHandle threadHandle, int milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool WriteProcessMemory(SafeProcessHandle processHandle, IntPtr baseAddress, ref byte buffer, int bufferSize, out int numberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool Wow64GetThreadContext(SafeThreadHandle threadHandle, ref Wow64Context context);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool Wow64SetThreadContext(SafeThreadHandle threadHandle, ref Wow64Context context);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern int Wow64SuspendThread(SafeThreadHandle threadHandle);
    }
}