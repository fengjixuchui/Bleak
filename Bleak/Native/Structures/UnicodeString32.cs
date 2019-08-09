using System;
using System.Runtime.InteropServices;

namespace Bleak.Native.Structures
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct UnicodeString32
    {
        internal readonly short Length;

        private readonly short MaximumLength;

        internal readonly int Buffer;

        internal UnicodeString32(string @string, IntPtr buffer)
        {
            Length = (short) (@string.Length * 2);

            MaximumLength = (short) (Length + 2);

            Buffer = (int) buffer;
        }
    }
}