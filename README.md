# firewall-manager
This library allow:
* Enable/Disable the firewall
* Authorize an application
* Open ports
* Add new Rules

## Usage
```c#
// initialize a FirewallCom
var firewall = new FirewallCom();
```

To help us to show some of the funcitonalities with create a method to display the fields of the type of generic objects
```c#
private static void DisplayTypeFields<T>(IEnumerable<T> collection)
{
    foreach (var item in collection)
    {
        foreach (var propertyInfo in item.GetType().GetFields())
            Console.WriteLine("{0}: {1}", propertyInfo.Name, propertyInfo.GetValue(item));
        Console.WriteLine();
    }
}
```

## Authorized App

#### List Authorized Apps
```c#
DisplayTypeFields(firewall.GetAuthorizeApps());
```

Print the list of authorized apps like
```c#
/*
Name: node.exe
IpVersion: Any
Enabled: True
Scope: All
RemoteAddresses: *
ProcessImageFileName: C:\users\alexander\appdata\roaming\nvm\v7.9.0\node.exe

Name: python
IpVersion: Any
Enabled: True
Scope: All
RemoteAddresses: *
ProcessImageFileName: C:\python27\python.exe

...
*/
```

#### Authorize an App
```c#
firewall.AddAuthorizeApp(new AuthorizeApp("Notepad", @"C:\Windows\Notepad.exe"));
```

This authorize the Notepad app. If you list the authorized apps you should get
```c#
/*
Name: Notepad
IpVersion: Any
Enabled: False
Scope: All
RemoteAddresses: *
ProcessImageFileName: C:\Windows\notepad.exe

Name: node.exe
IpVersion: Any
Enabled: True
Scope: All
RemoteAddresses: *
ProcessImageFileName: C:\users\alexander\appdata\roaming\nvm\v7.9.0\node.exe

Name: python
IpVersion: Any
Enabled: True
Scope: All
RemoteAddresses: *
ProcessImageFileName: C:\python27\python.exe

...
*/
```

#### Unauthorize an App
```c#
firewall.RemoveAuthorizeApp("Notepad");
```
To unauthorized the recent **notepad** app.

## Open Ports

#### List Open ports
```c#
DisplayTypeFields(firewall.GetOpenPorts());
```

Print the list of open ports like this:
```c#
/*
Name: OpenSSH
Port: 22
IpVersion: Any
Scope: All
ProtocolPort: Tcp
Enabled: True
RemoteAddresses: *

...
*/
```


#### Open a port
```c#
firewall.AddGloballyPort(new OpenPort("Custom Port", 2882));
```

This open the port **2882**. If you list the open ports you should get
```c#
/*
Name: Custom Port
Port: 2882
IpVersion: Any
Scope: All
ProtocolPort: Tcp
Enabled: False
RemoteAddresses: *

Name: OpenSSH
Port: 22
IpVersion: Any
Scope: All
ProtocolPort: Tcp
Enabled: True
RemoteAddresses: *

...
*/
```

#### Close the port
```c#
firewall.RemoveOpenPort("Custom Port");
```
To close the recent **Custom Port**.


## Advanced security

#### Enable / Disable Firewall
```c#
const ProfileType profileType = ProfileType.Domain;
Console.WriteLine("firewall enable: " + firewall.GetFirewallEnable(profileType));
Console.ReadKey();
firewall.SetFirewallEnable(profileType, !firewall.GetFirewallEnable(profileType));  // change the firewall status
Console.WriteLine("firewall enable: " + firewall.GetFirewallEnable(profileType));
Console.ReadKey();
firewall.SetFirewallEnable(profileType, !firewall.GetFirewallEnable(profileType));  // change the firewall status
Console.WriteLine("firewall enable: " + firewall.GetFirewallEnable(profileType));
Console.ReadKey();
```
If you run the code above you should get
```c#
/*
firewall enable: True
firewall enable: False
firewall enable: True
*/
```

#### List Firewall Rules
```c#
DisplayTypeFields(firewall.GetRules());
```

Print the list of rules like this:
```c#
/*
Action: Allow
ApplicationName: C:\Windows\notepad.exe
Description:
Direction: In
EdgeTraversal: False
Enabled: False
Grouping:
IcmpTypesAndCodes:
Interfaces:
InterfaceTypes: All
LocalAddresses: *
LocalPorts: *
Name: Notepad
Profiles: Public
Protocol: Udp
RemoteAddresses: *
RemotePorts: *
ServiceName:

...
*/
```

#### Add a new Rule
```c#
firewall.AddRule(new Rule(name: "Custom Rule", action: FirewallManager.Action.Allow));
```

This add a rule named **Custom Rule**. If you list the current rules you should get
```c#
/*
Action: Allow
ApplicationName:
Description:
Direction: In
EdgeTraversal: False
Enabled: False
Grouping:
IcmpTypesAndCodes:
Interfaces:
InterfaceTypes: All
LocalAddresses: *
LocalPorts:
Name: Custom Rule
Profiles: Domain
Protocol: Any
RemoteAddresses: *
RemotePorts:
ServiceName:

...
*/
```

#### Remove a rule
```c#
firewall.RemoveRule("Custom Rule");
```
To remove the recent **Custom Rule**.
