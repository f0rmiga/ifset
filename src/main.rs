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

use clap::{Arg, App};
use nix::sys::socket::{IpAddr, Ipv4Addr};
use std::error::Error;

mod ifsetup;
use ifsetup::{AddrSetter, Upper, RouteAdder, IfrName};

fn main() -> Result<(), Box<dyn Error>> {
    let matches = App::new("ifset")
        .version("0.1.0")
        .author("Thulio Ferraz Assis <thulio.assis@suse.com")
        .about("Sets up a network interface")
        .arg(Arg::with_name("name")
            .long("name")
            .help("The interface name")
            .takes_value(true))
        .arg(Arg::with_name("ipv4")
            .long("ipv4")
            .help("The IPv4 address to be assigned to the interface")
            .takes_value(true))
        .arg(Arg::with_name("route")
            .long("route")
            .help("The default route for the interface")
            .takes_value(true))
        .get_matches();

    let interface_name = matches.value_of("name").unwrap();
    let ipv4 = matches.value_of("ipv4").unwrap();
    let route = matches.value_of("route").unwrap();

    let ifs = ifsetup::IfSetup::new(IfrName::new(interface_name)?)?;

    ifs.set_addr(IpAddr::V4(Ipv4Addr::from_std(&ipv4.parse()?)))?;
    ifs.up()?;
    ifs.add_route(IpAddr::V4(Ipv4Addr::from_std(&route.parse()?)))?;

    Ok(())
}

