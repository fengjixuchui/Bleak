using static Bleak.Native.Enumerations;

namespace Bleak.PortableExecutable.Objects
{
    internal class Relocation
    {
        internal readonly ushort Offset;

        internal readonly RelocationType Type;

        internal Relocation(ushort offset, RelocationType type)
        {
            Offset = offset;

            Type = type;
        }
    }
}