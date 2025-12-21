using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Diagnostics;
 
namespace DEMO
{
    class Program
    {
        public static int HBase; //0x00509B74
        public static int Health = 0xF8;
 
 
 
        static void Main(string[] args)
        {
            Process[] processes = Process.GetProcessesByName("ac_client");
 
            int BaseAddress = processes[0].MainModule.BaseAddress.ToInt32();
 
            //Console.WriteLine(BaseAddress + 0x00109B74); //0x00109B74 is the value i need to add to "ac_client to get 0x00509B74"
            Console.WriteLine((BaseAddress + 0x00109B74).ToString("X4"));
        }
    }
}