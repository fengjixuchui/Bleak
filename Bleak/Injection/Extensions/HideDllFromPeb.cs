using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using Bleak.Injection.Objects;
using Bleak.Native.Structures;
using Bleak.RemoteProcess;

namespace Bleak.Injection.Extensions
{
    internal class HideDllFromPeb
    {
        private readonly string _dllPath;
        
        private readonly ManagedProcess _process;

        internal HideDllFromPeb(InjectionWrapper injectionWrapper)
        {
            _dllPath = injectionWrapper.DllPath;

            _process = injectionWrapper.Process;
        }

        internal void Call()
        {
            if (_process.IsWow64)
            {
                foreach (var (key, value) in _process.Peb.GetWow64PebEntries())
                {
                    // Read the file path of the entry
                    
                    var entryFilePathBytes = _process.MemoryManager.ReadVirtualMemory((IntPtr) value.FullDllName.Buffer, value.FullDllName.Length);

                    var entryFilePath = Encoding.Unicode.GetString(entryFilePathBytes);

                    if (entryFilePath != _dllPath)
                    {
                        continue;
                    }
                    
                    // Remove the entry from the InLoadOrder, InMemoryOrder and InInitializationOrder linked lists
                    
                    RemoveDoublyLinkedListEntry(value.InLoadOrderLinks);

                    RemoveDoublyLinkedListEntry(value.InMemoryOrderLinks);

                    RemoveDoublyLinkedListEntry(value.InInitializationOrderLinks);
                    
                    // Remove the entry from the LdrpHashTable
                    
                    RemoveDoublyLinkedListEntry(value.HashLinks);
                    
                    // Remove the entry from the LdrpModuleBaseAddressIndex

                    var rtlRbRemoveNodeAddress = _process.GetFunctionAddress("ntdll.dll", "RtlRbRemoveNode");

                    var ldrpModuleBaseAddressIndex = _process.PdbFile.Value.GetSymbolAddress(new Regex("LdrpModuleBaseAddressIndex"));

                    _process.CallFunction(CallingConvention.StdCall, rtlRbRemoveNodeAddress, (long) ldrpModuleBaseAddressIndex, (long) (key + (int) Marshal.OffsetOf<LdrDataTableEntry32>("BaseAddressIndexNode")));
                }
            }

            else
            {
                foreach (var (key, value) in _process.Peb.GetPebEntries())
                {
                    // Read the file path of the entry
                    
                    var entryFilePathBytes = _process.MemoryManager.ReadVirtualMemory((IntPtr) value.FullDllName.Buffer, value.FullDllName.Length);

                    var entryFilePath = Encoding.Unicode.GetString(entryFilePathBytes);

                    if (entryFilePath != _dllPath)
                    {
                        continue;
                    }
                    
                    // Remove the entry from the InLoadOrder, InMemoryOrder and InInitializationOrder linked lists
                    
                    RemoveDoublyLinkedListEntry(value.InLoadOrderLinks);

                    RemoveDoublyLinkedListEntry(value.InMemoryOrderLinks);

                    RemoveDoublyLinkedListEntry(value.InInitializationOrderLinks);
                    
                    // Remove the entry from the LdrpHashTable
                    
                    RemoveDoublyLinkedListEntry(value.HashLinks);
                    
                    // Remove the entry from the LdrpModuleBaseAddressIndex

                    var rtlRbRemoveNodeAddress = _process.GetFunctionAddress("ntdll.dll", "RtlRbRemoveNode");

                    var ldrpModuleBaseAddressIndex = _process.PdbFile.Value.GetSymbolAddress(new Regex("LdrpModuleBaseAddressIndex"));

                    _process.CallFunction(CallingConvention.StdCall, rtlRbRemoveNodeAddress, (long) ldrpModuleBaseAddressIndex, (long) (key + (int) Marshal.OffsetOf<LdrDataTableEntry64>("BaseAddressIndexNode")));
                }
            }
        }
        
        private void RemoveDoublyLinkedListEntry(ListEntry32 entry)
        {
            // Change the front link of the previous entry to the front link of the entry
            
            var previousEntry = _process.MemoryManager.ReadVirtualMemory<ListEntry32>((IntPtr) entry.Blink);

            previousEntry.Flink = entry.Flink;
            
            _process.MemoryManager.WriteVirtualMemory((IntPtr) entry.Blink, previousEntry);
            
            // Change the back link of the next entry to the back link of the entry
            
            var nextEntry = _process.MemoryManager.ReadVirtualMemory<ListEntry32>((IntPtr) entry.Flink);

            nextEntry.Blink = entry.Blink;
            
            _process.MemoryManager.WriteVirtualMemory((IntPtr) entry.Flink, nextEntry);
        }
        
        private void RemoveDoublyLinkedListEntry(ListEntry64 entry)
        {
            // Change the front link of the previous entry to the front link of the entry
            
            var previousEntry = _process.MemoryManager.ReadVirtualMemory<ListEntry64>((IntPtr) entry.Blink);

            previousEntry.Flink = entry.Flink;
            
            _process.MemoryManager.WriteVirtualMemory((IntPtr) entry.Blink, previousEntry);
            
            // Change the back link of the next entry to the back link of the entry
            
            var nextEntry = _process.MemoryManager.ReadVirtualMemory<ListEntry64>((IntPtr) entry.Flink);

            nextEntry.Blink = entry.Blink;
            
            _process.MemoryManager.WriteVirtualMemory((IntPtr) entry.Flink, nextEntry);
        }
    }
}