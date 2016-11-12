extern crate pnet;
extern crate rand;

use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::Packet;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{self, TcpPacket, TcpFlags, MutableTcpPacket};
use pnet::packet::icmp::{self, IcmpPacket};
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::transport;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::TransportChannelType::{Layer3, Layer4};

use rand::Rng;

use std::env;
use std::io;
use std::time;
use std::net::{IpAddr, Ipv4Addr};

static SOURCE_PORT: u16 = 59081;
static TIMEOUT: u64  = 1000;
static PORT_OPEN: u16 = TcpFlags::SYN | TcpFlags::ACK;
static PORT_CLOSED: u16 = TcpFlags::RST;

fn print_usage(program: &str) {
    println!("Usage: {} <target.ip> <port>", program);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = &args[0];
    if args.len() != 3 {
        print_usage(program);
        return;
    }

    let target = args[1].clone();
    let port = args[2].clone();

    let target = match target.parse::<Ipv4Addr>() {
        Ok(ip) => ip,
        Err(_) => panic!("{}: invalid ip address'{}'", program, target),
    };

    let (iface, source) = match route(&target) {
        Ok((iface, ip)) => (iface, ip),
        Err(e) => panic!("{}: unable to lookup '{}': {}", program, target, e),
    };

    let port = match port.parse::<u16>() {
        Ok(p) => p,
        Err(_) => panic!("{}: invalid port'{}'", program, port),
    };

    let mut buf = [0u8; 24];
    let syn_packet = build_syn_packet(port, &source, &target, &mut buf[..]);

    let (mut tx, _) = match transport::transport_channel(4096, Layer4(Ipv4(IpNextHeaderProtocols::Tcp))) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!("{}: unable to create channel: {}", program, e),
    };

    let (_, mut rx) = match datalink::channel(&iface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("{}: unhandled channel type.", program),
        Err(e) => panic!("{}: unable to create channel: {}", program, e),
    };

    let mut iter = rx.iter();
    let timeout = time::Duration::from_millis(TIMEOUT);
    let ts = time::SystemTime::now();
    tx.send_to(syn_packet, IpAddr::V4(target)).unwrap();
    loop {
        match iter.next() {
            Ok(packet) => {
                if let Some(ipv4_packet) = match packet.get_ethertype() {
                    EtherTypes::Ipv4 => Ipv4Packet::new(packet.payload()),
                    _ => None,
                } {
                    if ipv4_packet.get_source().eq(&target)
                        && ipv4_packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {

                        if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
                            if tcp_packet.get_source() == port {
                                let flags = tcp_packet.get_flags();
                                if (flags & PORT_OPEN) == PORT_OPEN {
                                    println!("{}:{}\topen", target, port);
                                    return
                                } else if (flags & PORT_CLOSED) == PORT_CLOSED {
                                    println!("{}:{}\tclosed", target, port);
                                    return
                                }
                            }
                        }
                    }
                }
            },
            Err(e) => panic!("{}: unable to read packet: {}", program, e),
        }
        if ts.elapsed().unwrap() > timeout {
            println!("{}:{}\tfiltered", target, port);
            return
        }
    }
}

fn build_syn_packet<'a>(dest: u16, source: &Ipv4Addr,
                    target: &Ipv4Addr, buf: &'a mut [u8]) -> MutableTcpPacket<'a> {
    //setting options
    buf[20] = 0x02; //Kind: Maximum Segment Size (2)
    buf[21] = 0x04; //Length: 4
    buf[22] = 0x05; //*
    buf[23] = 0xb4; //* MSS Value: 1460

    let sequence = rand::thread_rng().gen::<u32>();
    let mut packet = MutableTcpPacket::new(buf).unwrap();
    packet.set_source(SOURCE_PORT);
    packet.set_destination(dest);
    packet.set_sequence(sequence);
    packet.set_acknowledgement(0);
    packet.set_data_offset(6);
    packet.set_reserved(0b000);
    packet.set_flags(TcpFlags::SYN);
    packet.set_window(1024);
    packet.set_urgent_ptr(0);

    let checksum = tcp::ipv4_checksum(&packet.to_immutable(), *source, *target);

    packet.set_checksum(checksum);

    packet
}

fn route(target: &Ipv4Addr) -> Result<(NetworkInterface, Ipv4Addr), io::Error> {
    let mut buf = [0u8; 12];
    let identifier = rand::thread_rng().gen::<u16>();
    let mut icmp_request = MutableEchoRequestPacket::new(&mut buf).unwrap();
    icmp_request.set_icmp_type(icmp::IcmpType(8));
    icmp_request.set_identifier(identifier);
    icmp_request.set_sequence_number(1);
    let checksum = icmp::checksum(&IcmpPacket::new(icmp_request.packet()).unwrap());
    icmp_request.set_checksum(checksum);

    let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Icmp));
    let (mut tx, _) = match transport::transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => return Err(e),
    };

    let (_, mut rx) = match transport::transport_channel(4096, Layer3(IpNextHeaderProtocols::Icmp)) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => return Err(e),
    };

    let mut iter = transport::ipv4_packet_iter(&mut rx);
    tx.send_to(icmp_request, IpAddr::V4(*target)).unwrap();
    let ts = time::SystemTime::now();
    let timeout = time::Duration::from_millis(TIMEOUT);
    loop {
        match iter.next() {
            Ok((packet, _)) => {
                if packet.get_source().eq(target) {
                    let ip = packet.get_destination();
                    let interfaces = datalink::interfaces();
                    let filter = |iface: &NetworkInterface| {
                        if let Some(ref ips) = iface.ips {
                            ips.contains(&IpAddr::V4(ip))
                        } else {
                            false
                        }
                    };
                    let iface = interfaces.into_iter().filter(filter).next().unwrap();
                    return Ok((iface, ip))
                }
            },
            Err(e) => return Err(e),
        }
        if ts.elapsed().unwrap() > timeout {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "Request timed out"));
        }
    }
}
