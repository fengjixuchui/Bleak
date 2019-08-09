using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using Xunit;

namespace Bleak.Tests
{
    public class ExtensionTests : IDisposable
    {
        private readonly string _dllPath;

        private readonly Process _process;

        public ExtensionTests()
        {
            _dllPath = Path.Combine(Path.GetFullPath(@"..\..\..\Etc\"), "TestDll.dll");
            
            _process = new Process {StartInfo = {CreateNoWindow = true, FileName = "notepad.exe", UseShellExecute = true, WindowStyle = ProcessWindowStyle.Hidden}};
            
            _process.Start();

            _process.WaitForInputIdle();
        }
        
        public void Dispose()
        {
            _process.Kill();

            _process.Dispose();
        }

        [Fact]
        public void TestEjectDll()
        {
            using (var injector = new Injector(_process.Id, _dllPath, InjectionMethod.CreateThread))
            {
                injector.InjectDll();
                
                injector.EjectDll();
            }
            
            _process.Refresh();
            
            Assert.DoesNotContain(_process.Modules.Cast<ProcessModule>(), module => module.FileName == _dllPath);
        }
        
        [Fact]
        public void TestHideDllFromPeb()
        {
            using (var injector = new Injector(_process.Id, _dllPath, InjectionMethod.CreateThread, InjectionFlags.HideDllFromPeb))
            {
                injector.InjectDll();
            }

            _process.Refresh();

            Assert.DoesNotContain(_process.Modules.Cast<ProcessModule>(), module => module.FileName == _dllPath);
        }

        [Fact]
        public void TestRandomiseDllName()
        {
            using (var injector = new Injector(_process.Id, _dllPath, InjectionMethod.CreateThread, InjectionFlags.RandomiseDllName))
            {
                injector.InjectDll();
            }

            _process.Refresh();

            Assert.DoesNotContain(_process.Modules.Cast<ProcessModule>(), module => module.FileName == _dllPath);
        }
    }
}