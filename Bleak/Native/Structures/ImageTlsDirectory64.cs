using System.Runtime.InteropServices;

namespace Bleak.Native.Structures
{
    [StructLayout(LayoutKind.Explicit)]
    internal struct ImageTlsDirectory64
    {
        [FieldOffset(0x18)]
        internal readonly long AddressOfCallbacks;
    }
}