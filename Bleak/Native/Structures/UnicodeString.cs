using System.Runtime.InteropServices;

namespace Bleak.Native.Structures
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct UnicodeString<TPointer> where TPointer : struct
    {
        internal readonly short Length;

        private readonly short MaximumLength;

        internal TPointer Buffer;
    }
}