using System;
using System.Runtime.InteropServices;

namespace Bleak.Assembly.Objects
{
    internal class FunctionCall
    {
        internal readonly IntPtr FunctionAddress;
        
        internal readonly CallingConvention CallingConvention;

        internal readonly long[] Parameters;

        internal readonly IntPtr ReturnAddress;

        internal FunctionCall(IntPtr functionAddress, CallingConvention callingConvention, long[] parameters, IntPtr returnAddress)
        {
            FunctionAddress = functionAddress;

            CallingConvention = callingConvention;

            Parameters = parameters;

            ReturnAddress = returnAddress;
        }
    }
}