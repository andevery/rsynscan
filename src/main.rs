extern crate pnet;

// use pnet::datalink::{self, NetworkInterface};
// use pnet::datalink::Channel::Ethernet;
use pnet::transport;
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::{TcpPacket, TcpFlags, MutableTcpPacket};
use pnet::packet::Packet;

use std::env;
use std::net::{IpAddr, Ipv4Addr};

static SOURCE_PORT: u16 = 59081;

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

    let port = match port.parse::<u16>() {
        Ok(p) => p,
        Err(_) => panic!("{}: invalid port'{}'", program, port),
    };

    let mut buf = [0u8; 24];
    let syn_packet = build_syn_packet(port, &mut buf[..]);

    //
    // let filter = |iface: &NetworkInterface| {
    //     !iface.is_loopback() && iface.name == iface_name
    // };
    // let ifaces = datalink::interfaces();
    // let iface = match ifaces.into_iter().filter(filter).next() {
    //     Some(iface) => iface,
    //     None => panic!("{}: unable to find interface '{}'", program, iface_name),
    // };

    // let (_, mut rx) = match transport::transport_channel(65536, Layer4(Ipv4(IpNextHeaderProtocols::Tcp))) {
    //     Ok((tx, rx)) => (tx, rx),
    //     Err(e) => panic!("{}: unable to create channel: {}", program, e),
    // };
    //
    // let mut iter = transport::ipv4_packet_iter(&mut rx);
    // loop {
    //     match iter.next() {
    //         Ok((packet, addr)) => {
    //             if let Some(packet) = TcpPacket::new(packet.packet()) {
    //                 handle_tcp_packet(packet, addr)
    //             }
    //         },
    //         Err(e) => panic!("{}: unable to read packet: {}", program, e),
    //     };
    // }
}

fn build_syn_packet<'a>(dest: u16, buf: &'a mut [u8]) -> MutableTcpPacket<'a> {
    let mut packet = MutableTcpPacket::new(buf).unwrap();
    packet.set_source(SOURCE_PORT);
    packet.set_destination(dest);
    packet.set_sequence(0);
    packet.set_acknowledgement(0);
}

fn handle_tcp_packet(packet: TcpPacket, addr: IpAddr) {
    let syn_ack = TcpFlags::SYN | TcpFlags::ACK;
    if (packet.get_flags() & syn_ack) == syn_ack {
        println!("{:?}", packet.get_source());
    }
    // match packet.get_next_level_protocol() {
    //     IpNextHeaderProtocols::Tcp => println!("{:?}", packet.payload()),
    //     _ => println!("{:?}", packet.get_next_level_protocol()),
    // }
}
