namespace Bleak.PortableExecutable
{
    internal class PdbDebugData
    {
        internal readonly int Age;

        internal readonly string Guid;

        internal readonly string Name;

        internal PdbDebugData(int age, string guid, string name)
        {
            Age = age;

            Guid = guid;

            Name = name;
        }
    }
}