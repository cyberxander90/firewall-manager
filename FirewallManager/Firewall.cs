using System;
using System.Collections.Generic;
using System.Linq;

// reference to C:\Windows\System32\FirewallAPI.dll and C:\Windows\System32\hnetcfg.dll
using NetFwTypeLib;
//using NATUPNPLib;
//using NETCONLib;

namespace FirewallManager
{
    /// <summary>
    /// To handle the firewall using a COM object.
    /// </summary>
    public class FirewallCom
    {
        private readonly INetFwMgr _iNetFwMgr;
        private readonly INetFwPolicy2 _firewallPolicy;

        /// <summary>
        /// Initialize a FirewallCom.
        /// </summary>
        public FirewallCom()
        {
            // it works with both
            //_netFwMgrType = Type.GetTypeFromProgID("HNetCfg.FwMgr", false);
            var netFwMgrType = Type.GetTypeFromCLSID(new Guid("{304CE942-6E39-40D8-943A-B913C40C9CD4}"));

            _iNetFwMgr = (INetFwMgr)Activator.CreateInstance(netFwMgrType);
            _firewallPolicy = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
        }

        /// <summary>
        /// Get or set if the firewall is enable.
        /// Is recommended use the methods GetFirewallEnable and SetFirewallEnable.
        /// </summary>
        public bool Enable
        {
            get { return _iNetFwMgr.LocalPolicy.CurrentProfile.FirewallEnabled; }
            set { _iNetFwMgr.LocalPolicy.CurrentProfile.FirewallEnabled = value; }  // it turns false to true, but not in the other way
        }

        #region Authorized Apps

        /// <summary>
        /// Authorize an app to firewall.
        /// </summary>
        public void AddAuthorizeApp(AuthorizeApp authorizeApp)
        {
            // Create the type from prog id
            var type = Type.GetTypeFromProgID("HNetCfg.FwAuthorizedApplication");
            var fireWallAuthApp = Tools.Convert(() => (INetFwAuthorizedApplication)Activator.CreateInstance(type), authorizeApp);

            _iNetFwMgr.LocalPolicy.CurrentProfile.AuthorizedApplications.Add(fireWallAuthApp);
        }

        /// <summary>
        /// Get the Authorized apps.
        /// </summary>
        public IEnumerable<AuthorizeApp> GetAuthorizeApps()
        {
            return from INetFwAuthorizedApplication item in _iNetFwMgr.LocalPolicy.CurrentProfile.AuthorizedApplications select Tools.Convert(item);
        }

        /// <summary>
        /// Remove an authorize app from firewall.
        /// </summary>
        public void RemoveAuthorizeApp(string name)
        {
            var authApp = _iNetFwMgr.LocalPolicy.CurrentProfile.AuthorizedApplications
                .Cast<INetFwAuthorizedApplication>()
                .FirstOrDefault(item => item.Name == name);
            if (authApp != null)
                _iNetFwMgr.LocalPolicy.CurrentProfile.AuthorizedApplications.Remove(authApp.ProcessImageFileName);
        }

        #endregion

        #region PORTS

        /// <summary>
        /// Add a globally (open) port to firewall.
        /// </summary>
        public void AddGloballyPort(OpenPort openPort)
        {
            var type = Type.GetTypeFromProgID("HNetCfg.FWOpenPort");
            var firewallOpenPort = Tools.Convert(() => (INetFwOpenPort) Activator.CreateInstance(type), openPort);

            _iNetFwMgr.LocalPolicy.CurrentProfile.GloballyOpenPorts.Add(firewallOpenPort);
        }

        /// <summary>
        /// Get all globally (open) port firewall.
        /// </summary>
        public IEnumerable<OpenPort> GetOpenPorts()
        {
            return from INetFwOpenPort item in _iNetFwMgr.LocalPolicy.CurrentProfile.GloballyOpenPorts select Tools.Convert(item);
        }

        /// <summary>
        /// Remove a globally (open) port from firewall.
        /// </summary>
        public void RemoveOpenPort(string name)
        {
            var openPort = _iNetFwMgr.LocalPolicy.CurrentProfile.GloballyOpenPorts
                .Cast<INetFwOpenPort>()
                .FirstOrDefault(item => item.Name == name);
            if (openPort != null)
                _iNetFwMgr.LocalPolicy.CurrentProfile.GloballyOpenPorts.Remove(openPort.Port, openPort.Protocol);
        }

        #endregion

        #region ADVANCED SECURITY

        /// <summary>
        /// Get the firewall enable value.
        /// </summary>
        public bool GetFirewallEnable(ProfileType profileType)
        {
            return _firewallPolicy.FirewallEnabled[Tools.Convert(profileType)];
        }

        /// <summary>
        /// Set the firewall enable value.
        /// </summary>
        public void SetFirewallEnable(ProfileType profileType, bool value)
        {
            _firewallPolicy.FirewallEnabled[Tools.Convert(profileType)] = value;
        }

        /// <summary>
        /// Add rule to firewall.
        /// </summary>
        public void AddRule(Rule rule)
        {
            var firewallRule = Tools.Convert(() => (INetFwRule)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule")), rule);
            
            _firewallPolicy.Rules.Add(firewallRule);
        }

        /// <summary>
        /// Get the firewall rules.
        /// </summary>
        public IEnumerable<Rule> GetRules()
        {
            return from INetFwRule item in _firewallPolicy.Rules select Tools.Convert(item);
        }

        /// <summary>
        /// Remove rule from firewall.
        /// </summary>
        public void RemoveRule(string name)
        {
            _firewallPolicy.Rules.Remove(name);
        }

        #endregion
    }

    internal static class Tools
    {
        public static ProtocolPort Convert(NET_FW_IP_PROTOCOL_ item)
        {
            switch (item)
            {
                case NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_TCP: return ProtocolPort.Tcp;
                case NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_UDP: return ProtocolPort.Udp;
                default: return ProtocolPort.Any;
            }
        }
        public static NET_FW_IP_PROTOCOL_ Convert(ProtocolPort item)
        {
            switch (item)
            {
                case ProtocolPort.Tcp: return NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_TCP;
                case ProtocolPort.Udp: return NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_UDP;
                default: return NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_ANY;
            }
        }

        public static IpVersion Convert(NET_FW_IP_VERSION_ item)
        {
            switch (item)
            {
                case NET_FW_IP_VERSION_.NET_FW_IP_VERSION_MAX: return IpVersion.Max;
                case NET_FW_IP_VERSION_.NET_FW_IP_VERSION_V4: return IpVersion.V4;
                case NET_FW_IP_VERSION_.NET_FW_IP_VERSION_V6: return IpVersion.V6;
                default: return IpVersion.Any;
            }
        }
        public static NET_FW_IP_VERSION_ Convert(IpVersion item)
        {
            switch (item)
            {
                case IpVersion.Max: return NET_FW_IP_VERSION_.NET_FW_IP_VERSION_MAX;
                case IpVersion.V4: return NET_FW_IP_VERSION_.NET_FW_IP_VERSION_V4;
                case IpVersion.V6: return NET_FW_IP_VERSION_.NET_FW_IP_VERSION_V6;
                default: return NET_FW_IP_VERSION_.NET_FW_IP_VERSION_ANY;
            }
        }

        public static Scope Convert(NET_FW_SCOPE_ item)
        {
            switch (item)
            {
                case NET_FW_SCOPE_.NET_FW_SCOPE_CUSTOM: return Scope.Custom;
                case NET_FW_SCOPE_.NET_FW_SCOPE_LOCAL_SUBNET: return Scope.LocalSubnet;
                case NET_FW_SCOPE_.NET_FW_SCOPE_MAX: return Scope.Max;
                default: return Scope.All;
            }
        }
        public static NET_FW_SCOPE_ Convert(Scope item)
        {
            switch (item)
            {
                case Scope.Custom: return NET_FW_SCOPE_.NET_FW_SCOPE_CUSTOM;
                case Scope.LocalSubnet: return NET_FW_SCOPE_.NET_FW_SCOPE_LOCAL_SUBNET;
                case Scope.Max: return NET_FW_SCOPE_.NET_FW_SCOPE_MAX;
                default: return NET_FW_SCOPE_.NET_FW_SCOPE_ALL;
            }
        }

        public static ProfileType Convert(NET_FW_PROFILE_TYPE2_ item)
        {
            switch (item)
            {
                case NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN: return ProfileType.Domain;
                case NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE: return ProfileType.Private;
                case NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC: return ProfileType.Public;
                default: return ProfileType.All;
            }
        }
        public static NET_FW_PROFILE_TYPE2_ Convert(ProfileType item)
        {
            switch (item)
            {
                case ProfileType.Domain: return NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN;
                case ProfileType.Private: return NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE;
                case ProfileType.Public: return NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC;
                default: return NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_ALL;
            }
        }

        public static Action Convert(NET_FW_ACTION_ item)
        {
            switch (item)
            {
                case NET_FW_ACTION_.NET_FW_ACTION_ALLOW: return Action.Allow;
                case NET_FW_ACTION_.NET_FW_ACTION_BLOCK: return Action.Block;
                default: return Action.Max;
            }
        }
        public static NET_FW_ACTION_ Convert(Action item)
        {
            switch (item)
            {
                case Action.Allow: return NET_FW_ACTION_.NET_FW_ACTION_ALLOW;
                case Action.Block: return NET_FW_ACTION_.NET_FW_ACTION_BLOCK;
                default: return NET_FW_ACTION_.NET_FW_ACTION_MAX;
            }
        }

        public static Direction Convert(NET_FW_RULE_DIRECTION_ item)
        {
            switch (item)
            {
                case NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN: return Direction.In;
                case NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_OUT: return Direction.Out;
                default: return Direction.Max;
            }
        }
        public static NET_FW_RULE_DIRECTION_ Convert(Direction item)
        {
            switch (item)
            {
                case Direction.In: return NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN;
                case Direction.Out: return NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_OUT;
                default: return NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_MAX;
            }
        }


        public static AuthorizeApp Convert(INetFwAuthorizedApplication item)
        {
            return new AuthorizeApp
            {
                Enabled = item.Enabled,
                IpVersion = Convert(item.IpVersion),
                Name = item.Name,
                ProcessImageFileName = item.ProcessImageFileName,
                RemoteAddresses = item.RemoteAddresses,
                Scope = Convert(item.Scope)
            };
        }
        public static INetFwAuthorizedApplication Convert(Func<INetFwAuthorizedApplication> func, AuthorizeApp item)
        {
            var result = func();
            result.Enabled = item.Enabled;
            result.IpVersion = Convert(item.IpVersion);
            result.Name = item.Name;
            result.ProcessImageFileName = item.ProcessImageFileName;
            result.RemoteAddresses = item.RemoteAddresses;
            result.Scope = Convert(item.Scope);

            return result;
        }

        public static OpenPort Convert(INetFwOpenPort item)
        {
            return new OpenPort
            {
                Enabled = item.Enabled,
                IpVersion = Convert(item.IpVersion),
                Name = item.Name,
                RemoteAddresses = item.RemoteAddresses,
                Scope = Convert(item.Scope),
                Port = item.Port,
                ProtocolPort = Convert(item.Protocol)
            };
        }
        public static INetFwOpenPort Convert(Func<INetFwOpenPort> func, OpenPort item)
        {
            var result = func();
            result.Enabled = item.Enabled;
            result.IpVersion = Convert(item.IpVersion);
            result.Name = item.Name;
            result.RemoteAddresses = item.RemoteAddresses;
            result.Scope = Convert(item.Scope);
            result.Port = item.Port;
            result.Protocol = Convert(item.ProtocolPort);

            return result;
        }

        public static Rule Convert(INetFwRule item)
        {
            return new Rule
            {
                Action = Convert(item.Action),
                ApplicationName = item.ApplicationName,
                Description = item.Description,
                Direction = Convert(item.Direction),
                EdgeTraversal = item.EdgeTraversal,
                Enabled = item.Enabled,
                Grouping = item.Grouping,
                IcmpTypesAndCodes = item.IcmpTypesAndCodes,
                InterfaceTypes = item.InterfaceTypes,
                Interfaces = item.Interfaces,
                LocalAddresses = item.LocalAddresses,
                LocalPorts = item.LocalPorts,
                Name = item.Name,
                Profiles = Convert((NET_FW_PROFILE_TYPE2_) item.Profiles),
                Protocol = Convert((NET_FW_IP_PROTOCOL_) item.Protocol),
                RemoteAddresses = item.RemoteAddresses,
                RemotePorts = item.RemotePorts,
                ServiceName = item.serviceName
            };
        }
        public static INetFwRule Convert(Func<INetFwRule> func, Rule item)
        {
            var result = func();
            result.Action = Convert(item.Action);
            result.ApplicationName = item.ApplicationName;
            result.Description = item.Description;
            result.Direction = Convert(item.Direction);
            result.EdgeTraversal = item.EdgeTraversal;
            result.Enabled = item.Enabled;
            result.Grouping = item.Grouping;
            if (item.IcmpTypesAndCodes != null) result.IcmpTypesAndCodes = item.IcmpTypesAndCodes;  // it can't be null
            result.InterfaceTypes = item.InterfaceTypes;
            result.Interfaces = item.Interfaces;
            result.LocalAddresses = item.LocalAddresses;
            if (item.LocalPorts != null) result.LocalPorts = item.LocalPorts;  // it can't be null
            result.Name = item.Name;
            result.Profiles = (int)Convert(item.Profiles);
            result.Protocol = (int)Convert(item.Protocol);
            result.RemoteAddresses = item.RemoteAddresses;
            if (item.RemotePorts != null) result.RemotePorts = item.RemotePorts;
            result.serviceName = item.ServiceName;

            return result;
        }
    }


// ReSharper disable CSharpWarnings::CS1591
    public struct AuthorizeApp
    {
        public AuthorizeApp(string name, string processImageFileName, IpVersion ipVersion = IpVersion.Any, Scope scope = Scope.All)
            : this()
        {
            Name = name;
            ProcessImageFileName = processImageFileName;
            IpVersion = ipVersion;
            Scope = scope;
        }

        public string Name;
        public IpVersion IpVersion;
        public bool Enabled;
        public Scope Scope;
        public string RemoteAddresses;
        public string ProcessImageFileName;
    }

    public struct OpenPort
    {
        public OpenPort(string name, int port, IpVersion ipVersion = IpVersion.Any, Scope scope = Scope.All, ProtocolPort protocolPort = ProtocolPort.Tcp) : this()
        {
            Name = name;
            Port = port;
            IpVersion = ipVersion;
            Scope = scope;
            ProtocolPort = protocolPort;
        }

        public string Name;
        public int Port;
        public IpVersion IpVersion;
        public Scope Scope;
        public ProtocolPort ProtocolPort;
        public bool Enabled;
        public string RemoteAddresses;
    }

    public struct Rule
    {
        public Rule(string name, Action action, ProfileType profileType = ProfileType.Domain, ProtocolPort protocolPort = ProtocolPort.Any, string interfaceTypes = "All", string localAddress = "*", string remoteAddress = "*")
            : this()
        {
            Name = name;
            Action = action;
            Profiles = profileType;
            Protocol = protocolPort;
            InterfaceTypes = interfaceTypes;
            LocalAddresses = localAddress;
            RemoteAddresses = remoteAddress;
        }

        public Action Action;
        public string ApplicationName;
        public string Description;
        public Direction Direction;
        public bool EdgeTraversal;
        public bool Enabled;
        public string Grouping;
        public string IcmpTypesAndCodes;
        public dynamic Interfaces;
        public string InterfaceTypes;
        public string LocalAddresses;
        public string LocalPorts;
        public string Name;
        public ProfileType Profiles;
        public ProtocolPort Protocol;
        public string RemoteAddresses;
        public string RemotePorts;
        public string ServiceName;
    }


    public enum ProtocolPort
    {
        Any, Tcp, Udp
    }

    public enum IpVersion
    {
        Any, Max, V4, V6
    }

    public enum Scope
    {
        All, Custom, LocalSubnet, Max
    }

    public enum ProfileType
    {
        All, Domain, Private, Public
    }

    public enum Action
    {
        Allow, Block, Max
    }

    public enum Direction
    {
        In, Out, Max
    }
// ReSharper restore CSharpWarnings::CS1591
}

