using System.Runtime.InteropServices;

namespace Bleak.Native.Structures
{
    [StructLayout(LayoutKind.Explicit)]
    internal struct ApiSetNamespace
    {
        [FieldOffset(0x0C)]
        internal readonly int Count;

        [FieldOffset(0x10)]
        internal readonly int EntryOffset;
    }
}