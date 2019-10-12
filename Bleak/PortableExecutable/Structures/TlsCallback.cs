namespace Bleak.PortableExecutable.Structures
{
    internal sealed class TlsCallback
    {
        internal readonly int Offset;

        internal TlsCallback(int offset)
        {
            Offset = offset;
        }
    }
}