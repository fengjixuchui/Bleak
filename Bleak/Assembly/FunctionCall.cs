using System;
using System.Runtime.InteropServices;

namespace Bleak.Assembly
{
    internal class FunctionCall
    {
        internal readonly bool IsWow64;

        internal readonly IntPtr FunctionAddress;

        internal readonly CallingConvention CallingConvention;

        internal readonly long[] Parameters;

        internal readonly IntPtr ReturnAddress;

        internal FunctionCall(bool isWow64, IntPtr functionAddress, CallingConvention callingConvention, long[] parameters, IntPtr returnAddress)
        {
            IsWow64 = isWow64;

            FunctionAddress = functionAddress;

            CallingConvention = callingConvention;

            Parameters = parameters;

            ReturnAddress = returnAddress;
        }
    }
}