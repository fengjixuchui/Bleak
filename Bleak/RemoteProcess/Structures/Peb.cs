using System;

namespace Bleak.RemoteProcess.Structures
{
    internal sealed class Peb
    {
        internal readonly IntPtr ApiSetMapAddress;

        internal readonly IntPtr LoaderAddress;

        internal Peb(IntPtr apiSetMapAddress, IntPtr loaderAddress)
        {
            ApiSetMapAddress = apiSetMapAddress;

            LoaderAddress = loaderAddress;
        }
    }
}