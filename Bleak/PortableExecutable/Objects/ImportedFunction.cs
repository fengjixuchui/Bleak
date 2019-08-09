namespace Bleak.PortableExecutable.Objects
{
    internal class ImportedFunction
    {
        internal string Dll;

        internal readonly string Name;

        internal readonly int Offset;

        internal readonly short Ordinal;

        internal ImportedFunction(string dll, string name, int offset, short ordinal)
        {
            Dll = dll;

            Name = name;

            Offset = offset;

            Ordinal = ordinal;
        }
    }
}