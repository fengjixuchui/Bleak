using System;
using System.Runtime.InteropServices;
using Bleak.Native.Enumerations;
using Bleak.Native.SafeHandle;
using Microsoft.Win32.SafeHandles;

namespace Bleak.Native.PInvoke
{
    internal static class Ntdll
    {
        [DllImport("ntdll.dll")]
        internal static extern NtStatus NtCreateThreadEx(out SafeThreadHandle threadHandle, AccessMask desiredAccess, IntPtr objectAttributes, SafeProcessHandle processHandle, IntPtr startAddress, IntPtr parameter, ThreadCreationFlags creationFlags, int zeroBits, int stackSize, int maximumStackSize, IntPtr attributeList);

        [DllImport("ntdll.dll")]
        internal static extern NtStatus NtQueryInformationProcess(SafeProcessHandle processHandle, ProcessInformationClass processInformationClass, ref byte buffer, int bufferSize, out int returnLength);

        [DllImport("ntdll.dll")]
        internal static extern int RtlNtStatusToDosError(NtStatus ntStatus);
    }
}