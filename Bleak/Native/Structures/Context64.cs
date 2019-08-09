using System.Runtime.InteropServices;
using Bleak.Native.Enumerations;

namespace Bleak.Native.Structures
{
    [StructLayout(LayoutKind.Explicit, Pack = 16, Size = 1232)]
    internal struct Context64
    {
        [FieldOffset(0x30)]
        internal ContextFlags ContextFlags;

        [FieldOffset(0x80)] 
        internal long Rcx;
        
        [FieldOffset(0x98)]
        internal long Rsp;
        
        [FieldOffset(0xF8)]
        internal long Rip;
    }
}