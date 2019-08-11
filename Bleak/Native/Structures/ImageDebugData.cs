using System;
using System.Runtime.InteropServices;

namespace Bleak.Native.Structures
{
    [StructLayout(LayoutKind.Explicit)]
    internal struct ImageDebugData
    {
        [FieldOffset(0x04)]
        internal readonly Guid Guid;

        [FieldOffset(0x14)]
        internal readonly int Age;
    }
}