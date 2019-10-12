using System.Collections.Generic;

namespace Bleak.PortableExecutable.Structures
{
    internal sealed class BaseRelocation
    {
        internal readonly int Offset;

        internal readonly List<Relocation> Relocations;

        internal BaseRelocation(int offset, List<Relocation> relocations)
        {
            Offset = offset;

            Relocations = relocations;
        }
    }
}