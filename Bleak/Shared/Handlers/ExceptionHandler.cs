using System.ComponentModel;
using System.Runtime.InteropServices;
using static Bleak.Native.Enumerations;
using static Bleak.Native.PInvoke;

namespace Bleak.Shared.Handlers
{
    internal static class ExceptionHandler
    {
        internal static void ThrowWin32Exception(string message)
        {
            // Get the error code associated with the last PInvoke error

            var lastWin32ErrorCode = Marshal.GetLastWin32Error();

            throw new Win32Exception($"{message} with error code {lastWin32ErrorCode}");
        }
        
        internal static void ThrowWin32Exception(string message, NtStatus ntStatus)
        {
            // Convert the NT Status to a DOS error code

            var dosErrorCode = RtlNtStatusToDosError(ntStatus);

            throw new Win32Exception($"{message} with error code {dosErrorCode}");
        }
    }
}