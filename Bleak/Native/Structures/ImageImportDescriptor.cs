using System.Runtime.InteropServices;

namespace Bleak.Native.Structures
{
    [StructLayout(LayoutKind.Explicit, Size = 20)]
    internal struct ImageImportDescriptor
    {
        [FieldOffset(0x00)]
        internal readonly int OriginalFirstThunk;

        [FieldOffset(0x0C)]
        internal readonly int Name;

        [FieldOffset(0x10)]
        internal readonly int FirstThunk;
    }
}