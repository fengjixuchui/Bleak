using System;
using System.Runtime.InteropServices;
using Bleak.Native.Enumerations;
using Bleak.Native.SafeHandle;
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
        internal static extern SafeThreadHandle OpenThread(int desiredAccess, bool inheritHandle, int threadId);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool ReadProcessMemory(SafeProcessHandle processHandle, IntPtr baseAddress, IntPtr bytesRead, int bytesToRead, IntPtr numberOfBytesRead);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern int ResumeThread(SafeThreadHandle threadHandle);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool SetThreadContext(SafeThreadHandle threadHandle, IntPtr context);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern int SuspendThread(SafeThreadHandle threadHandle);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr VirtualAllocEx(SafeProcessHandle processHandle, IntPtr baseAddress, int allocationSize, MemoryAllocationType allocationType, MemoryProtectionType protectionType);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool VirtualFreeEx(SafeProcessHandle processHandle, IntPtr baseAddress, int freeSize, MemoryFreeType freeType);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool VirtualProtectEx(SafeProcessHandle processHandle, IntPtr baseAddress, int protectionSize, MemoryProtectionType protectionType, out MemoryProtectionType oldProtectionType);
        
        [DllImport("kernel32.dll")]
        internal static extern void WaitForSingleObject(SafeThreadHandle handle, int millisecondsToWait);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool Wow64GetThreadContext(SafeThreadHandle threadHandle, IntPtr context);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool Wow64SetThreadContext(SafeThreadHandle threadHandle, IntPtr context);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern int Wow64SuspendThread(SafeThreadHandle threadHandle);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool WriteProcessMemory(SafeProcessHandle processHandle, IntPtr baseAddress, IntPtr bufferToWrite, int bytesToWrite, IntPtr numberOfBytesWritten);
    }
}