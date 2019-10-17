using System;
using System.Runtime.InteropServices;

namespace Bleak.RemoteProcess.Structures
{
    internal sealed class CallDescriptor
    {
        internal readonly CallingConvention CallingConvention;

        internal readonly IntPtr FunctionAddress;

        internal readonly bool IsWow64Call;

        internal readonly long[] Parameters;

        internal readonly IntPtr ReturnAddress;

        internal CallDescriptor(CallingConvention callingConvention, IntPtr functionAddress, bool isWow64Call, long[] parameters, IntPtr returnAddress)
        {
            CallingConvention = callingConvention;

            FunctionAddress = functionAddress;

            IsWow64Call = isWow64Call;

            Parameters = parameters;

            ReturnAddress = returnAddress;
        }
    }
}