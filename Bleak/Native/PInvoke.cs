using System;
using System.Runtime.InteropServices;
using Bleak.Native.SafeHandle;
using Microsoft.Win32.SafeHandles;

namespace Bleak.Native
{
    internal static class PInvoke
    {
        // kernel32.dll imports

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool GetThreadContext(SafeThreadHandle threadHandle, IntPtr contextBuffer);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool IsWow64Process(SafeProcessHandle processHandle, out bool isWow64Process);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern SafeThreadHandle OpenThread(Enumerations.ThreadAccessMask desiredAccess, bool inheritHandle, int threadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool ReadProcessMemory(SafeProcessHandle processHandle, IntPtr baseAddress, IntPtr bytesReadBuffer, int bytesToRead, IntPtr numberOfBytesReadBuffer);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern int ResumeThread(SafeThreadHandle threadHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool SetThreadContext(SafeThreadHandle threadHandle, IntPtr contextBuffer);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern int SuspendThread(SafeThreadHandle threadHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr VirtualAllocEx(SafeProcessHandle processHandle, IntPtr baseAddress, int allocationSize, Enumerations.AllocationType allocationType, Enumerations.MemoryProtection protectionType);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool VirtualFreeEx(SafeProcessHandle processHandle, IntPtr baseAddress, int freeSize, Enumerations.FreeType freeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool VirtualProtectEx(SafeProcessHandle processHandle, IntPtr baseAddress, int protectionSize, Enumerations.MemoryProtection protectionType, out Enumerations.MemoryProtection oldProtectionType);

        [DllImport("kernel32.dll")]
        internal static extern void WaitForSingleObject(SafeThreadHandle handle, int millisecondsToWait);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool Wow64GetThreadContext(SafeThreadHandle threadHandle, IntPtr contextBuffer);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool Wow64SetThreadContext(SafeThreadHandle threadHandle, IntPtr contextBuffer);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern int Wow64SuspendThread(SafeThreadHandle threadHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool WriteProcessMemory(SafeProcessHandle processHandle, IntPtr baseAddress, IntPtr bufferToWrite, int bufferSize, IntPtr numberOfBytesWrittenBuffer);

        // ntdll.dll imports

        [DllImport("ntdll.dll", SetLastError = true)]
        internal static extern Enumerations.NtStatus NtCreateThreadEx(out SafeThreadHandle threadHandle, Enumerations.ThreadAccessMask desiredAccess, IntPtr objectAttributesBuffer, SafeProcessHandle processHandle, IntPtr startAddress, IntPtr parameter, Enumerations.ThreadCreationType creationType, IntPtr stackZeroBits, IntPtr sizeOfStack, IntPtr maximumStackSize, IntPtr attributeListBuffer);

        [DllImport("ntdll.dll", SetLastError = true)]
        internal static extern Enumerations.NtStatus NtQueryInformationProcess(SafeProcessHandle processHandle, Enumerations.ProcessInformationClass processInformationClass, IntPtr processInformationBuffer, int bufferSize, IntPtr returnLength);

        [DllImport("ntdll.dll", SetLastError = true)]
        internal static extern Enumerations.NtStatus RtlCreateUserThread(SafeProcessHandle processHandle, IntPtr securityDescriptorBuffer, bool createSuspended, int stackZeroBits, IntPtr stackReserved, IntPtr stackCommit, IntPtr startAddress, IntPtr parameter, out SafeThreadHandle threadHandle, out IntPtr clientIdBuffer);

        [DllImport("ntdll.dll", SetLastError = true)]
        internal static extern Enumerations.NtStatus RtlGetVersion(out Structures.OsVersionInfo versionInformation);

        // user32.dll functions

        [DllImport("user32.dll")]
        internal static extern void SwitchToThisWindow(IntPtr windowHandle, bool altTab);
    }
}