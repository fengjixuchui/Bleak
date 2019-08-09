using System.Runtime.InteropServices;

namespace Bleak.Native.Structures
{
    [StructLayout(LayoutKind.Explicit)]
    internal struct Peb32
    {
        [FieldOffset(0x0C)]
        internal readonly int Ldr;
        
        [FieldOffset(0x38)] 
        internal readonly int ApiSetMap;
    }
}