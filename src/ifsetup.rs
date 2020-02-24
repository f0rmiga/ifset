// Copyright 2020 Thulio Ferraz Assis
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::mem;
use std::os::unix::io::RawFd;

use nix::sys::socket;
use nix::unistd::close;

pub trait AddrSetter {
    fn set_addr(&self, addr: socket::IpAddr) -> nix::Result<()>;
}

pub trait Upper {
    fn up(&self) -> nix::Result<()>;
}

pub trait RouteAdder {
    fn add_route(&self, route: socket::IpAddr) -> nix::Result<()>;
}

pub struct IfSetup {
    sockfd_provider: fn () -> nix::Result<RawFd>,
    name: IfrName,
}

impl IfSetup {
    pub fn new(name: IfrName) -> nix::Result<Self> {
        Ok(IfSetup{
            sockfd_provider: inet_sockfd,
            name: name,
        })
    }
}

impl AddrSetter for IfSetup {
    fn set_addr(&self, addr: socket::IpAddr) -> nix::Result<()> {
        let ifr_addr = {
            let inet_addr = socket::InetAddr::new(addr, 0);
            let sock_addr = socket::SockAddr::new_inet(inet_addr);
            let (csockaddr, _) = unsafe { sock_addr.as_ffi_pair() };
            *csockaddr
        };
        let ifr = ifreq{
            ifr_name: self.name,
            _union: ifreq_union{
                ifr_addr: ifr_addr,
            },
        };

        let sockfd = (self.sockfd_provider)()?;
        unsafe { libc::ioctl(sockfd, libc::SIOCSIFADDR, &ifr) };
        close(sockfd)
    }
}

impl Upper for IfSetup {
    fn up(&self) -> nix::Result<()> {
        let ifr = ifreq{
            ifr_name: self.name,
            _union: ifreq_union{
                ifr_flags: libc::IFF_RUNNING as libc::c_short | libc::IFF_UP as libc::c_short,
            },
        };

        let sockfd = (self.sockfd_provider)()?;
        unsafe { libc::ioctl(sockfd, libc::SIOCSIFFLAGS, &ifr) };
        close(sockfd)
    }
}

impl RouteAdder for IfSetup {
    fn add_route(&self, route: socket::IpAddr) -> nix::Result<()> {
        let rt_dev = self.name.as_ptr() as *mut i8;

        let csockaddr_gateway = {
            let inet_addr = socket::InetAddr::new(route, 0);
            let sock_addr = socket::SockAddr::new_inet(inet_addr);
            let (csockaddr, _) = unsafe { sock_addr.as_ffi_pair() };
            *csockaddr
        };

        let csockaddr_any = {
            let inet_addr = socket::InetAddr::new(socket::IpAddr::V4(socket::Ipv4Addr::any()), 0);
            let sock_addr = socket::SockAddr::new_inet(inet_addr);
            let (csockaddr, _) = unsafe { sock_addr.as_ffi_pair() };
            *csockaddr
        };

        let route = libc::rtentry{
            rt_gateway: csockaddr_gateway,
            rt_dst: csockaddr_any,
            rt_genmask: csockaddr_any,
            rt_flags: libc::RTF_UP | libc::RTF_GATEWAY,
            rt_dev: rt_dev,
            rt_pad1: 0,
            rt_pad2: 0,
            rt_pad3: 0,
            rt_pad4: [0; 3],
            rt_tos: 0,
            rt_class: 0,
            rt_metric: 1,
            rt_mtu: 1500,
            rt_window: 0,
            rt_irtt: 0,
        };

        let sockfd = (self.sockfd_provider)()?;
        unsafe { libc::ioctl(sockfd, libc::SIOCADDRT, &route) };
        close(sockfd)
    }
}

fn inet_sockfd() -> nix::Result<RawFd> {
    socket::socket(
        socket::AddressFamily::Inet,
        socket::SockType::Datagram,
        socket::SockFlag::empty(),
        None,
    )
}

#[derive(Copy, Clone, Default)]
pub struct IfrName([u8; libc::IFNAMSIZ]);

impl IfrName {
    pub fn new(name: &str) -> Result<Self, std::io::Error> {
        let name_bytes = name.as_bytes();
        if name_bytes.len() > libc::IFNAMSIZ {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, ""));
        }
        let mut ifr_name: IfrName = unsafe { mem::zeroed() };
        ifr_name.0[..name_bytes.len()].copy_from_slice(name_bytes);
        Ok(ifr_name)
    }

    pub fn as_ptr(&self) -> *const Self { self }
}

#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct ifreq {
    pub ifr_name: IfrName,
    pub _union: ifreq_union,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub union ifreq_union {
    pub ifr_addr: libc::sockaddr,
    pub ifr_dstaddr: libc::sockaddr,
    pub ifr_broadaddr: libc::sockaddr,
    pub ifr_netmask: libc::sockaddr,
    pub ifr_hwaddr: libc::sockaddr,
    pub ifr_flags: libc::c_short,
    pub ifr_ifindex: libc::c_int,
    pub ifr_metric: libc::c_int,
    pub ifr_mtu: libc::c_int,
    pub ifr_map: ifmap,
    pub ifr_slave: [libc::c_char; libc::IFNAMSIZ],
    pub ifr_newname: [libc::c_char; libc::IFNAMSIZ],
    pub ifr_data: *mut libc::c_char,
}

impl Default for ifreq_union {
    fn default() -> Self { unsafe { mem::zeroed() } }
}

#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct ifmap {
    pub mem_start: libc::c_ulong,
    pub mem_end: libc::c_ulong,
    pub base_addr: libc::c_ushort,
    pub irq: libc::c_uchar,
    pub dma: libc::c_uchar,
    pub port: libc::c_uchar,
}
