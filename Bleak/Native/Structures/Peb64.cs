using System.Runtime.InteropServices;

namespace Bleak.Native.Structures
{
    [StructLayout(LayoutKind.Explicit)]
    internal struct Peb64
    {
        [FieldOffset(0x18)]
        internal readonly long Ldr;

        [FieldOffset(0x68)] 
        internal readonly long ApiSetMap;
    }
}