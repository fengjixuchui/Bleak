namespace Bleak.PortableExecutable.Structures
{
    internal sealed class DebugData
    {
        internal readonly int Age;

        internal readonly string Guid;

        internal readonly string Name;

        internal DebugData(int age, string guid, string name)
        {
            Age = age;

            Guid = guid;

            Name = name;
        }
    }
}