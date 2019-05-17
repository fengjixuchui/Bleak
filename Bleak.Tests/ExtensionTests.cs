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

        public void Dispose()
        {
            _process.Kill();

            _process.Dispose();
        }

        public ExtensionTests()
        {
            _dllPath = Path.Combine(Path.GetFullPath(@"..\..\..\Etc\"), "TestDll.dll");

            _process = new Process { StartInfo = { CreateNoWindow = true, FileName = "notepad.exe", UseShellExecute = true, WindowStyle = ProcessWindowStyle.Hidden } };

            _process.Start();

            _process.WaitForInputIdle();
        }

        [Fact]
        public void TestEjectDll()
        {
            using (var injector = new Injector(InjectionMethod.CreateThread, _process.Id, _dllPath))
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
            using (var injector = new Injector(InjectionMethod.CreateThread, _process.Id, _dllPath))
            {
                injector.InjectDll();

                injector.HideDllFromPeb();
            }

            _process.Refresh();

            Assert.DoesNotContain(_process.Modules.Cast<ProcessModule>(), module => module.FileName == _dllPath);
        }

        [Fact]
        public void RandomiseDllHeaders()
        {
            using (var injector = new Injector(InjectionMethod.CreateThread, _process.Id, _dllPath))
            {
                injector.InjectDll();

                Assert.True(injector.RandomiseDllHeaders());
            }
        }
    }
}