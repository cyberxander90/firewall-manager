using System;
using FirewallManager;
using System.Collections.Generic;

namespace ConsoleApplication1
{
    class Program
    {
        public static void Main(string[] args)
        {
            // initialize a FirewallCom
            var firewall = new FirewallCom();

            #region Authorized App

            //// get
            //DisplayTypeFields(firewall.GetAuthorizeApps());
            ///*
            //Name: cypress.exe
            //IpVersion: Any
            //Enabled: True
            //Scope: All
            //RemoteAddresses: *
            //ProcessImageFileName: C:\users\alexander\appdata\local\cypress\cache\3.0.1\cypress\cypress.exe

            //Name: node.exe
            //IpVersion: Any
            //Enabled: True
            //Scope: All
            //RemoteAddresses: *
            //ProcessImageFileName: C:\users\alexander\appdata\roaming\nvm\v7.9.0\node.exe

            //Name: python
            //IpVersion: Any
            //Enabled: True
            //Scope: All
            //RemoteAddresses: *
            //ProcessImageFileName: C:\python27\python.exe
            //...
            //*/

            //// add
            //firewall.AddAuthorizeApp(new AuthorizeApp("Notepad", @"C:\Windows\Notepad.exe"));
            ///*
            //Name: Notepad
            //IpVersion: Any
            //Enabled: False
            //Scope: All
            //RemoteAddresses: *
            //ProcessImageFileName: C:\Windows\notepad.exe
            //...
            //*/

            //// remove
            //firewall.RemoveAuthorizeApp("Notepad");

            #endregion

            #region Open port

            //// get open ports
            //DisplayTypeFields(firewall.GetOpenPorts());
            ///*
            //Name: OpenSSH
            //Port: 22
            //IpVersion: Any
            //Scope: All
            //ProtocolPort: Tcp
            //Enabled: True
            //RemoteAddresses: *
            //...
            //*/

            //// add
            //firewall.AddGloballyPort(new OpenPort("Custom Port", 2882));
            ///*
            //Name: Custom Port
            //Port: 2882
            //IpVersion: Any
            //Scope: All
            //ProtocolPort: Tcp
            //Enabled: False
            //RemoteAddresses: *
            //...
            //*/

            //// remove
            //firewall.RemoveOpenPort("Custom Port");

            #endregion

            #region Advanced security

            //// firewall on/off
            //const ProfileType profileType = ProfileType.Domain;
            //Console.WriteLine("firewall enable: " + firewall.GetFirewallEnable(profileType));
            //Console.ReadKey();
            //firewall.SetFirewallEnable(profileType, !firewall.GetFirewallEnable(profileType));  // change the firewall status
            //Console.WriteLine("firewall enable: " + firewall.GetFirewallEnable(profileType));
            //Console.ReadKey();
            //firewall.SetFirewallEnable(profileType, !firewall.GetFirewallEnable(profileType));  // // change the firewall status
            //Console.WriteLine("firewall enable: " + firewall.GetFirewallEnable(profileType));
            //Console.ReadKey();

            //// get rules
            //DisplayTypeFields(firewall.GetRules());
            ///*
            //Action: Allow
            //ApplicationName: C:\Windows\notepad.exe
            //Description:
            //Direction: In
            //EdgeTraversal: False
            //Enabled: False
            //Grouping:
            //IcmpTypesAndCodes:
            //Interfaces:
            //InterfaceTypes: All
            //LocalAddresses: *
            //LocalPorts: *
            //Name: Notepad
            //Profiles: Public
            //Protocol: Udp
            //RemoteAddresses: *
            //RemotePorts: *
            //ServiceName:
            //...
            //*/

            //// add rule
            //firewall.AddRule(new Rule(name: "Custom Rule", action: FirewallManager.Action.Allow));
            ///*
            //Action: Allow
            //ApplicationName:
            //Description:
            //Direction: In
            //EdgeTraversal: False
            //Enabled: False
            //Grouping:
            //IcmpTypesAndCodes:
            //Interfaces:
            //InterfaceTypes: All
            //LocalAddresses: *
            //LocalPorts:
            //Name: Custom Rule
            //Profiles: Domain
            //Protocol: Any
            //RemoteAddresses: *
            //RemotePorts:
            //ServiceName:
            //...
            //*/

            //// remove rule
            //firewall.RemoveRule("Custom Rule");

            #endregion

            Console.ReadKey();
        }

        private static void DisplayTypeFields<T>(IEnumerable<T> collection)
        {
            foreach (var item in collection)
            {
                foreach (var propertyInfo in item.GetType().GetFields())
                    Console.WriteLine("{0}: {1}", propertyInfo.Name, propertyInfo.GetValue(item));
                Console.WriteLine();
                Console.ReadKey();
            }
        }
    }
}
