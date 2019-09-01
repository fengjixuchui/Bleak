using System;
using Bleak.Native.Enumerations;
using Bleak.Native.PInvoke;

namespace Bleak.Exceptions
{
    internal class RemoteFunctionCallException : Exception
    {
        internal RemoteFunctionCallException(string message) : base($"{message} in the remote process") { }

        internal RemoteFunctionCallException(string message, NtStatus ntStatus) : base($"{message} in the remote process with error code {Ntdll.RtlNtStatusToDosError(ntStatus)}") { }
    }
}