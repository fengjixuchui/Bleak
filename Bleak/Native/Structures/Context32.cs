using System.Runtime.InteropServices;
using Bleak.Native.Enumerations;

namespace Bleak.Native.Structures
{
    [StructLayout(LayoutKind.Explicit, Size = 716)]
    internal struct Context32
    {
        [FieldOffset(0x00)]
        internal ContextFlags ContextFlags;

        [FieldOffset(0xB0)] 
        internal int Eax;
        
        [FieldOffset(0xB8)]
        internal int Eip;

        [FieldOffset(0xC4)]
        internal int Esp;
    }
}