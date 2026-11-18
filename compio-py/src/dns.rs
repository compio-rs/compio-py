use hickory_proto::rr::RData;
use hickory_resolver::lookup::Lookup;
use pyo3::{Bound, IntoPyObject, PyErr, Python, types::PyTuple};
use std::net::SocketAddr;

#[cfg(unix)]
use libc::AI_CANONNAME;

#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::AI_CANONNAME;

/*
Code below is based off this structure
with an additonal feature for setting up a domain to lookup.
struct addrinfo {
    int              ai_flags;
    int              ai_family;
    int              ai_socktype;
    int              ai_protocol;
    size_t           ai_addrlen;
    struct sockaddr *ai_addr;
    char            *ai_canonname;
    struct addrinfo *ai_next;
};
*/

#[doc = "Used for naming lookups carriable object, it's disposed 
of after lookup is done."]
#[derive(Clone)]
pub struct Domain {
    pub host: String,
    pub port: u16
}

impl From<(&str, u16)> for Domain {
    fn from(value: (&str, u16)) -> Self {
        Self{host: value.0.to_string(), port: value.1}
    }
}


#[derive(Clone)]
pub enum Address {
    Domain(Domain),
    Addr(SocketAddr)
}


#[derive(Clone)]
pub struct AddrInfo {
    pub flags: u32,
    pub family: u16,
    pub socktype: u32,
    pub protocol: u32,
    pub cannonname: String,
    pub addr: Address
}

impl AddrInfo {
    pub fn host(&self) -> String {
        match &self.addr {
            Address::Domain(d) => {d.host.clone()},
            Address::Addr(addr) => {addr.ip().to_string()}
        }
    }
    pub fn port(&self) -> u16 {
        match &self.addr {
            Address::Domain(d) => {d.port},
            Address::Addr(addr) => {addr.port()}
        }
    }
}

impl<'py> IntoPyObject<'py> for AddrInfo {
    type Target = PyTuple; // The Python type (e.g., PyAny, PyDict, PyList)
    type Output = Bound<'py, Self::Target>; // Typically Bound for owned conversions
    type Error = PyErr; // Must be convertible to PyErr

    fn into_pyobject(self, py: Python<'py>) -> Result<Self::Output, Self::Error> {
        // Convert Rust fields to Python objects
        let addr = (self.host(), self.port()).into_pyobject(py)?;
        (
            self.family, self.socktype, self.protocol, self.cannonname, addr
        ).into_pyobject(py)
    }
}


#[derive(Clone)]
pub struct AddrInfoBuilder {
    pub flags: Option<u32>,
    pub family: Option<u16>,
    pub socktype: Option<u32>,
    pub protocol: Option<u32>,
    pub cannonname: Option<String>,
    pub addr:Option<Address>,
}

impl AddrInfoBuilder {
    pub fn set_cannonname(mut self, cannonname: String) -> Self {
        self.cannonname.replace(cannonname);
        self
    }
    
    pub fn set_addr(mut self, addr: SocketAddr) -> Self {
        self.addr.replace(Address::Addr(addr));
        self
    }

    pub fn set_domain(mut self, name: &str, port: u16) -> Self{
        self.addr.replace(
            Address::Domain(Domain{host:name.to_string(), port:port})
        );
        self
    }

    pub fn set_flags(mut self, flags:u32) -> Self {
        self.flags.replace(flags);
        self
    }

    pub fn set_family(mut self, family: u16) -> Self {
        self.family.replace(family);
        self
    }
  
    pub fn set_socktype(mut self, socktype: u32) -> Self {
        self.socktype.replace(socktype);
        self
    }

    pub fn set_proto(mut self, proto: u32) -> Self {
        self.protocol.replace(proto);
        self
    }

    pub fn build(&self) -> AddrInfo {
        self.into()
    }
}


impl Default for AddrInfoBuilder {
    fn default() -> Self {
        Self {
            flags: None, 
            family: None, 
            socktype: None, 
            protocol: None, 
            cannonname: None, 
            addr: None
        }
    }
}

impl From<&AddrInfoBuilder> for AddrInfo {
    fn from(value: &AddrInfoBuilder) -> Self {
        Self {
            flags: value.flags.unwrap_or(0),
            family: value.family.unwrap_or(0),
            socktype: value.socktype.unwrap_or(0),
            protocol: value.protocol.unwrap_or(0),
            cannonname: value.cannonname.clone().unwrap_or(String::new()),
            addr: value.addr.clone().unwrap()
        }
    }
}

impl From<&AddrInfo> for AddrInfoBuilder {
    fn from(value: &AddrInfo) -> Self {
        Self { 
            flags: Some(value.flags), 
            family: Some(value.family), 
            socktype: Some(value.socktype), 
            protocol: Some(value.protocol), 
            cannonname: Some(value.cannonname.clone()), 
            addr: Some(value.addr.clone()) 
        }
    }
}


#[doc="Parses dns lookups based off a real getaddrinfo function"]
pub fn parse_getaddrinfo(
    hints: &AddrInfo,
    lookups: &[Lookup]
) -> Vec<AddrInfo> {
    let mut addrs = Vec::<AddrInfo>::new();

    for lookup in lookups {
        for record in lookup.answers() {
            let mut builder: AddrInfoBuilder = hints.into();
            
            match record.data {
                RData::A(a) => {
                    builder = builder.set_addr(SocketAddr::new(a.0.into(), hints.port()));
                }
                RData::AAAA(aaaa) => {
                    builder = builder.set_addr(SocketAddr::new(aaaa.0.into(), hints.port()));
                }
                _ => {continue;}
            }
            // NOTE: Vizonex (I only know of AI_CANNONAME at the moment.)
            if (hints.flags & AI_CANONNAME) > 0 {
                /* set the lookup name when setting it to hints earlier. */
                builder = builder.set_cannonname(hints.host());
            }
            addrs.push(builder.build());
        }
    }
    return addrs;
}




