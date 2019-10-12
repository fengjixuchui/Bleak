namespace Bleak.PortableExecutable.Structures
{
    internal sealed class ImportedFunction
    {
        internal string DllName;

        internal readonly string Name;

        internal readonly int Offset;

        internal readonly short Ordinal;

        internal ImportedFunction(string dllName, string name, int offset, short ordinal)
        {
            DllName = dllName;

            Name = name;

            Offset = offset;

            Ordinal = ordinal;
        }
    }
}