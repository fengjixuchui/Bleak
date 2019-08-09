using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Bleak.Native.Structures;
using Bleak.PortableExecutable;
using Bleak.RemoteProcess;

namespace Bleak.Injection.Objects
{
    internal class InjectionWrapper
    {
        internal readonly byte[] DllBytes;
        
        internal readonly string DllPath;

        internal readonly InjectionMethod InjectionMethod;
        
        internal readonly InjectionFlags InjectionFlags;

        internal readonly PeImage PeImage;

        internal readonly ManagedProcess Process;

        internal InjectionWrapper(Process process, byte[] dllBytes, InjectionMethod injectionMethod, InjectionFlags injectionFlags)
        {
            DllBytes = dllBytes;

            if (injectionMethod != InjectionMethod.ManualMap)
            {
                DllPath = CreateTemporaryDll();
            }
            
            InjectionMethod = injectionMethod;
            
            InjectionFlags = injectionFlags;
            
            PeImage = new PeImage(dllBytes);

            Process = new ManagedProcess(process);
            
            if (injectionMethod == InjectionMethod.ManualMap || injectionFlags.HasFlag(InjectionFlags.HideDllFromPeb))
            {
                ResolveApiSetImportedFunctions();
            }
        }
        
        internal InjectionWrapper(Process process, string dllPath, InjectionMethod injectionMethod, InjectionFlags injectionFlags)
        {
            DllBytes = File.ReadAllBytes(dllPath);

            DllPath = injectionFlags.HasFlag(InjectionFlags.RandomiseDllName) ? CreateTemporaryDll() : dllPath;

            InjectionMethod = injectionMethod;
            
            InjectionFlags = injectionFlags;
            
            PeImage = new PeImage(DllBytes);

            Process = new ManagedProcess(process);
            
            if (injectionMethod == InjectionMethod.ManualMap || injectionFlags.HasFlag(InjectionFlags.HideDllFromPeb))
            {
                ResolveApiSetImportedFunctions();
            }
        }
        
        private string CreateTemporaryDll()
        {
            // Create a directory to store the temporary DLL

            var temporaryDirectoryInfo = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "Bleak", "DLL"));

            // Clear the directory

            foreach (var file in temporaryDirectoryInfo.GetFiles())
            {
                try
                {
                    file.Delete();
                }

                catch (Exception)
                {
                    // The file is currently open and cannot be safely deleted
                }
            }

            // Create a temporary DLL

            var temporaryDllPath = Path.Combine(temporaryDirectoryInfo.FullName, Path.GetRandomFileName() + ".dll");

            try
            {
                File.WriteAllBytes(temporaryDllPath, DllBytes);
            }

            catch (IOException)
            {
                // A DLL already exists with the specified name and is loaded in a process and cannot be safely overwritten
            }

            return temporaryDllPath;
        }
        
        private void ResolveApiSetImportedFunctions()
        {
            if (!PeImage.ImportedFunctions.Value.Exists(function => function.Dll.StartsWith("api-ms")))
            {
                return;
            }

            // Read the entries of the API set
            
            var apiSetNamespace = Process.MemoryManager.ReadVirtualMemory<ApiSetNamespace>(Process.Peb.ApiSetMapAddress);
            
            var apiSetMappings = new Dictionary<string, string>();

            for (var namespaceEntryIndex = 0; namespaceEntryIndex < apiSetNamespace.Count; namespaceEntryIndex ++)
            {
                // Read the name of the namespace entry
                
                var namespaceEntry = Process.MemoryManager.ReadVirtualMemory<ApiSetNamespaceEntry>(Process.Peb.ApiSetMapAddress + apiSetNamespace.EntryOffset + Marshal.SizeOf<ApiSetNamespaceEntry>() * namespaceEntryIndex);
                
                var namespaceEntryNameBytes = Process.MemoryManager.ReadVirtualMemory(Process.Peb.ApiSetMapAddress + namespaceEntry.NameOffset, namespaceEntry.NameLength);

                var namespaceEntryName = Encoding.Unicode.GetString(namespaceEntryNameBytes) + ".dll";
                
                // Read the name of the value entry that the namespace entry maps to
                
                var valueEntry = Process.MemoryManager.ReadVirtualMemory<ApiSetValueEntry>(Process.Peb.ApiSetMapAddress + namespaceEntry.ValueOffset);
                
                var valueEntryNameBytes = Process.MemoryManager.ReadVirtualMemory(Process.Peb.ApiSetMapAddress + valueEntry.ValueOffset, valueEntry.ValueCount);
                
                var valueEntryName = Encoding.Unicode.GetString(valueEntryNameBytes);
                
                apiSetMappings.Add(namespaceEntryName, valueEntryName);
            }
            
            foreach (var function in PeImage.ImportedFunctions.Value.FindAll(f => f.Dll.StartsWith("api-ms")))
            {
                function.Dll = apiSetMappings[function.Dll];
            }
        }
    }
}