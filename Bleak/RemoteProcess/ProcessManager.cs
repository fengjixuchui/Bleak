using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using Bleak.Assembly;
using Bleak.Exceptions;
using Bleak.Native;
using Bleak.Native.Enumerations;
using Bleak.Native.PInvoke;
using Bleak.Native.Structures;
using Bleak.ProgramDatabase;
using Bleak.Memory;

namespace Bleak.RemoteProcess
{
    internal class ProcessManager : IDisposable
    {
        internal readonly bool IsWow64;

        internal readonly List<Module> Modules;

        internal readonly Lazy<PdbFile> PdbFile;

        internal readonly PebManager PebManager;

        internal readonly Process Process;

        internal ProcessManager(Process process)
        {
            Process = process;

            EnableDebuggerPrivileges();

            IsWow64 = IsWow64Process();

            PebManager = new PebManager(IsWow64, Process.SafeHandle);

            Modules = GetModules();

            PdbFile = new Lazy<PdbFile>(() => new PdbFile(Modules.Find(module => module.Name.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase)), IsWow64));
        }

        public void Dispose()
        {
            Process.Dispose();
        }

        internal void CallFunction(CallingConvention callingConvention, IntPtr functionAddress, params long[] parameters)
        {
            CallFunctionInternal(new FunctionCall(IsWow64, functionAddress, callingConvention, parameters, IntPtr.Zero));
        }

        internal TStructure CallFunction<TStructure>(CallingConvention callingConvention, IntPtr functionAddress, params long[] parameters) where TStructure : struct
        {
            var returnAddress = MemoryManager.AllocateVirtualMemory(Process.SafeHandle, IntPtr.Zero, Marshal.SizeOf<TStructure>(), MemoryProtectionType.ReadWrite);

            CallFunctionInternal(new FunctionCall(IsWow64, functionAddress, callingConvention, parameters, returnAddress));

            try
            {
                return MemoryManager.ReadVirtualMemory<TStructure>(Process.SafeHandle, returnAddress);
            }

            finally
            {
                MemoryManager.FreeVirtualMemory(Process.SafeHandle, returnAddress);
            }
        }

        internal IntPtr GetFunctionAddress(string moduleName, string functionName)
        {
            // Search the module list for the module

            var module = Modules.Find(m => m.Name.Equals(moduleName, StringComparison.OrdinalIgnoreCase));

            if (module is null)
            {
                return IntPtr.Zero;
            }

            // Calculate the address of the function

            var function = module.PeImage.Value.ExportedFunctions.Find(f => f.Name != null && f.Name == functionName);

            var functionAddress = module.BaseAddress + function.Offset;

            // Calculate the start and end address of the export directory

            var exportDirectory = module.PeImage.Value.PeHeaders.PEHeader.ExportTableDirectory;

            var exportDirectoryStartAddress = module.BaseAddress + exportDirectory.RelativeVirtualAddress;

            var exportDirectoryEndAddress = exportDirectoryStartAddress + exportDirectory.Size;

            // Determine if the function is forwarded to another function

            if ((long) functionAddress < (long) exportDirectoryStartAddress || (long) functionAddress > (long) exportDirectoryEndAddress)
            {
                return functionAddress;
            }

            // Read the forwarded function

            var forwardedFunctionBytes = new List<byte>();

            while (true)
            {
                var currentByte = MemoryManager.ReadVirtualMemory<byte>(Process.SafeHandle, functionAddress);

                if (currentByte == 0x00)
                {
                    break;
                }

                forwardedFunctionBytes.Add(currentByte);

                functionAddress += 1;
            }

            var forwardedFunction = Encoding.ASCII.GetString(forwardedFunctionBytes.ToArray()).Split('.');

            return GetFunctionAddress(forwardedFunction[0] + ".dll", forwardedFunction[1]);
        }

        internal IntPtr GetFunctionAddress(string moduleName, short functionOrdinal)
        {
            // Search the module list for the module

            var module = Modules.Find(m => m.Name.Equals(moduleName, StringComparison.OrdinalIgnoreCase));

            if (module is null)
            {
                return IntPtr.Zero;
            }

            // Find the name of the function

            var function = module.PeImage.Value.ExportedFunctions.Find(f => f.Ordinal == functionOrdinal);

            return GetFunctionAddress(moduleName, function.Name);
        }

        internal void Refresh()
        {
            Modules.Clear();

            Modules.AddRange(GetModules());

            Process.Refresh();
        }

        private void CallFunctionInternal(FunctionCall functionCall)
        {
            // Write the shellcode used to perform the function call into the remote process

            var shellcode = Assembler.AssembleFunctionCall(functionCall);

            var shellcodeAddress = MemoryManager.AllocateVirtualMemory(Process.SafeHandle, IntPtr.Zero, shellcode.Length, MemoryProtectionType.ReadWrite);

            MemoryManager.WriteVirtualMemory(Process.SafeHandle, shellcodeAddress, shellcode);

            MemoryManager.ProtectVirtualMemory(Process.SafeHandle, shellcodeAddress, shellcode.Length, MemoryProtectionType.ExecuteRead);

            // Create a thread to execute the shellcode in the remote process

            var ntStatus = Ntdll.NtCreateThreadEx(out var threadHandle, Constants.ThreadAllAccess, IntPtr.Zero, Process.SafeHandle, Modules[0].BaseAddress, IntPtr.Zero, ThreadCreationFlags.CreateSuspended | ThreadCreationFlags.HideFromDebugger, 0, 0, 0, IntPtr.Zero);

            if (ntStatus != NtStatus.Success)
            {
                throw new PInvokeException("Failed to call NtCreateThreadEx", ntStatus);
            }

            if (IsWow64)
            {
                // Get the context of the thread

                var threadContext = new Context32 {ContextFlags = ContextFlags.Integer};

                var threadContextBuffer = Marshal.AllocHGlobal(Marshal.SizeOf<Context32>());

                Marshal.StructureToPtr(threadContext, threadContextBuffer, false);

                if (!Kernel32.Wow64GetThreadContext(threadHandle, threadContextBuffer))
                {
                    throw new PInvokeException("Failed to call Wow64GetThreadContext");
                }

                threadContext = Marshal.PtrToStructure<Context32>(threadContextBuffer);

                // Change the spoofed start address to the address of the shellcode

                threadContext.Eax = (int) shellcodeAddress;

                Marshal.StructureToPtr(threadContext, threadContextBuffer, false);

                // Update the context of the thread

                if (!Kernel32.Wow64SetThreadContext(threadHandle, threadContextBuffer))
                {
                    throw new PInvokeException("Failed to call Wow64SetThreadContext");
                }

                Marshal.FreeHGlobal(threadContextBuffer);
            }

            else
            {
                // Get the context of the thread

                var threadContext = new Context64 {ContextFlags = ContextFlags.Integer};

                var threadContextBuffer = Marshal.AllocHGlobal(Marshal.SizeOf<Context64>());

                Marshal.StructureToPtr(threadContext, threadContextBuffer, false);

                if (!Kernel32.GetThreadContext(threadHandle, threadContextBuffer))
                {
                    throw new PInvokeException("Failed to call GetThreadContext");
                }

                threadContext = Marshal.PtrToStructure<Context64>(threadContextBuffer);

                // Change the spoofed start address to the address of the shellcode

                threadContext.Rcx = (long) shellcodeAddress;

                Marshal.StructureToPtr(threadContext, threadContextBuffer, false);

                // Update the context of the thread

                if (!Kernel32.SetThreadContext(threadHandle, threadContextBuffer))
                {
                    throw new PInvokeException("Failed to call SetThreadContext");
                }

                Marshal.FreeHGlobal(threadContextBuffer);
            }

            Kernel32.ResumeThread(threadHandle);

            Kernel32.WaitForSingleObject(threadHandle, int.MaxValue);

            threadHandle.Dispose();

            MemoryManager.FreeVirtualMemory(Process.SafeHandle, shellcodeAddress);
        }

        private void EnableDebuggerPrivileges()
        {
            try
            {
                Process.EnterDebugMode();
            }

            catch (Win32Exception)
            {
                // The local process isn't running in administrator mode
            }
        }

        private List<Module> GetModules()
        {
            var modules = new List<Module>();

            if (IsWow64)
            {
                var filePathRegex = new Regex("System32", RegexOptions.IgnoreCase);

                foreach (var entry in PebManager.GetWow64PebEntries().Values)
                {
                    // Read the file path of the entry

                    var entryFilePathBytes = MemoryManager.ReadVirtualMemory(Process.SafeHandle, (IntPtr) entry.FullDllName.Buffer, entry.FullDllName.Length);

                    var entryFilePath = filePathRegex.Replace(Encoding.Unicode.GetString(entryFilePathBytes), "SysWOW64");

                    // Read the name of the entry

                    var entryNameBytes = MemoryManager.ReadVirtualMemory(Process.SafeHandle, (IntPtr) entry.BaseDllName.Buffer, entry.BaseDllName.Length);

                    var entryName = Encoding.Unicode.GetString(entryNameBytes);

                    modules.Add(new Module((IntPtr) entry.DllBase, entryFilePath, entryName));
                }
            }

            else
            {
                foreach (var entry in PebManager.GetPebEntries().Values)
                {
                    // Read the file path of the entry

                    var entryFilePathBytes = MemoryManager.ReadVirtualMemory(Process.SafeHandle, (IntPtr) entry.FullDllName.Buffer, entry.FullDllName.Length);

                    var entryFilePath = Encoding.Unicode.GetString(entryFilePathBytes);

                    // Read the name of the entry

                    var entryNameBytes = MemoryManager.ReadVirtualMemory(Process.SafeHandle, (IntPtr) entry.BaseDllName.Buffer, entry.BaseDllName.Length);

                    var entryName = Encoding.Unicode.GetString(entryNameBytes);

                    modules.Add(new Module((IntPtr) entry.DllBase, entryFilePath, entryName));
                }
            }

            return modules;
        }

        private bool IsWow64Process()
        {
            if (!Kernel32.IsWow64Process(Process.SafeHandle, out var isWow64Process))
            {
                throw new PInvokeException("Failed to call IsWow64Process");
            }

            return isWow64Process;
        }
    }
}