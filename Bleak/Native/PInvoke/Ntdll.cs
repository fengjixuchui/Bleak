using System;
using System.Runtime.InteropServices;
using Bleak.Native.Enumerations;
using Bleak.Native.SafeHandle;
using Microsoft.Win32.SafeHandles;

namespace Bleak.Native.PInvoke
{
    internal static class Ntdll
    {
        [DllImport("ntdll.dll", SetLastError = true)]
        internal static extern NtStatus NtCreateThreadEx(out SafeThreadHandle threadHandle, int desiredAccess, IntPtr objectAttributes, SafeProcessHandle processHandle, IntPtr startAddress, IntPtr parameter, ThreadCreationFlags creationFlags, int zeroBits, int stackSize, int maximumStackSize, IntPtr attributeList);
        
        [DllImport("ntdll.dll", SetLastError = true)]
        internal static extern NtStatus NtQueryInformationProcess(SafeProcessHandle processHandle, ProcessInformationClass processInformationClass, IntPtr processInformation, int bufferSize, IntPtr returnLength);
        
        [DllImport("ntdll.dll", SetLastError = true)]
        internal static extern NtStatus  NtUnmapViewOfSection(SafeProcessHandle processHandle, IntPtr baseAddress);
        
        [DllImport("ntdll.dll", SetLastError = true)]
        internal static extern int RtlNtStatusToDosError(NtStatus ntStatus);
    }
}