using System;
using System.Runtime.InteropServices;
using Bleak.Native.Enumerations;
using Bleak.Native.PInvoke;

namespace Bleak.Shared.Exceptions
{
    internal class PInvokeException : Exception
    {
        internal PInvokeException(string message) : base($"{message} with error code {Marshal.GetLastWin32Error()}") { }
        
        internal PInvokeException(string message, NtStatus ntStatus) : base($"{message} with error code {Ntdll.RtlNtStatusToDosError(ntStatus)}") { }
    }
}