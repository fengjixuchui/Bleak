using System;
using System.Text;
using System.Text.RegularExpressions;
using Bleak.Injection.Interfaces;
using Bleak.Injection.Objects;
using static Bleak.Native.Structures;

namespace Bleak.Injection.Extensions
{
    internal class HideDllFromPeb : IInjectionExtension
    {
        private readonly InjectionWrapper _injectionWrapper;

        public HideDllFromPeb(InjectionWrapper injectionWrapper)
        {
            _injectionWrapper = injectionWrapper;
        }
        
        public bool Call(InjectionContext injectionContext)
        {
            foreach (var pebEntry in _injectionWrapper.ProcessManager.GetPebEntries())
            {
                var filePathRegex = new Regex("System32", RegexOptions.IgnoreCase);
                
                if (_injectionWrapper.ProcessManager.IsWow64)
                {
                    var loaderEntry = (LdrDataTableEntry32) pebEntry.LoaderEntry;
                    
                    // Read the file path of the entry

                    var entryFilePathBytes = _injectionWrapper.MemoryManager.ReadVirtualMemory((IntPtr) loaderEntry.FullDllName.Buffer, loaderEntry.FullDllName.Length);

                    var entryFilePath = filePathRegex.Replace(Encoding.Unicode.GetString(entryFilePathBytes), "SysWOW64");

                    if (entryFilePath != _injectionWrapper.DllPath)
                    {
                        continue;
                    }
                    
                    // Remove the entry from the doubly linked lists

                    RemoveDoublyLinkedListEntry(loaderEntry.InLoadOrderLinks);

                    RemoveDoublyLinkedListEntry(loaderEntry.InMemoryOrderLinks);

                    RemoveDoublyLinkedListEntry(loaderEntry.InInitializationOrderLinks);

                    // Remove the entry from the LdrpHashTable

                    RemoveDoublyLinkedListEntry(loaderEntry.HashLinks);

                    // Write over the DLL name and path

                    _injectionWrapper.MemoryManager.WriteVirtualMemory((IntPtr) loaderEntry.BaseDllName.Buffer, new byte[loaderEntry.BaseDllName.MaximumLength]);

                    _injectionWrapper.MemoryManager.WriteVirtualMemory((IntPtr) loaderEntry.FullDllName.Buffer, new byte[loaderEntry.FullDllName.MaximumLength]);
                }

                else
                {
                    var loaderEntry = (LdrDataTableEntry64) pebEntry.LoaderEntry;
                    
                    // Read the file path of the entry

                    var entryFilePathBytes = _injectionWrapper.MemoryManager.ReadVirtualMemory((IntPtr) loaderEntry.FullDllName.Buffer, loaderEntry.FullDllName.Length);

                    var entryFilePath = Encoding.Unicode.GetString(entryFilePathBytes);

                    if (entryFilePath != _injectionWrapper.DllPath)
                    {
                        continue;
                    }
                    
                    // Remove the entry from the doubly linked lists

                    RemoveDoublyLinkedListEntry(loaderEntry.InLoadOrderLinks);

                    RemoveDoublyLinkedListEntry(loaderEntry.InMemoryOrderLinks);

                    RemoveDoublyLinkedListEntry(loaderEntry.InInitializationOrderLinks);

                    // Remove the entry from the LdrpHashTable

                    RemoveDoublyLinkedListEntry(loaderEntry.HashLinks);

                    // Write over the DLL name and path

                    _injectionWrapper.MemoryManager.WriteVirtualMemory((IntPtr) loaderEntry.BaseDllName.Buffer, new byte[loaderEntry.BaseDllName.MaximumLength]);

                    _injectionWrapper.MemoryManager.WriteVirtualMemory((IntPtr) loaderEntry.FullDllName.Buffer, new byte[loaderEntry.FullDllName.MaximumLength]);
                }
            }
            
            return true;
        }
        
        private void RemoveDoublyLinkedListEntry(ListEntry32 entry)
        {
            // Read the previous entry from the list

            var previousEntry = _injectionWrapper.MemoryManager.ReadVirtualMemory<ListEntry32>((IntPtr) entry.Blink);

            // Change the front link of the previous entry to the front link of the entry

            previousEntry.Flink = entry.Flink;

            _injectionWrapper.MemoryManager.WriteVirtualMemory((IntPtr) entry.Blink, previousEntry);

            // Read the next entry from the list

            var nextEntry = _injectionWrapper.MemoryManager.ReadVirtualMemory<ListEntry32>((IntPtr) entry.Flink);

            // Change the back link of the next entry to the back link of the entry

            nextEntry.Blink = entry.Blink;

            _injectionWrapper.MemoryManager.WriteVirtualMemory((IntPtr) entry.Flink, nextEntry);
        }

        private void RemoveDoublyLinkedListEntry(ListEntry64 entry)
        {
            // Read the previous entry from the list

            var previousEntry = _injectionWrapper.MemoryManager.ReadVirtualMemory<ListEntry64>((IntPtr) entry.Blink);

            // Change the front link of the previous entry to the front link of the entry

            previousEntry.Flink = entry.Flink;

            _injectionWrapper.MemoryManager.WriteVirtualMemory((IntPtr) entry.Blink, previousEntry);

            // Read the next entry from the list

            var nextEntry = _injectionWrapper.MemoryManager.ReadVirtualMemory<ListEntry64>((IntPtr) entry.Flink);

            // Change the back link of the next entry to the back link of the entry

            nextEntry.Blink = entry.Blink;

            _injectionWrapper.MemoryManager.WriteVirtualMemory((IntPtr) entry.Flink, nextEntry);
        }
    }
}