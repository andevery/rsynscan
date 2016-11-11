extern crate pnet;
extern crate rand;

// use pnet::datalink::{self, NetworkInterface};
// use pnet::datalink::Channel::Ethernet;
use pnet::transport;
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::{self, TcpPacket, TcpFlags, MutableTcpPacket};
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::{self, IcmpPacket};
use pnet::packet::Packet;

use std::env;
use std::net::{IpAddr, Ipv4Addr};
use rand::Rng;

static SOURCE_PORT: u16 = 59081;

fn print_usage(program: &str) {
    println!("Usage: {} <source.ip> <target.ip> <port>", program);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = &args[0];
    if args.len() != 4 {
        print_usage(program);
        return;
    }

    let source = args[1].clone();
    let target = args[2].clone();
    let port = args[3].clone();

    let source = match source.parse::<Ipv4Addr>() {
        Ok(ip) => ip,
        Err(_) => panic!("{}: invalid ip address'{}'", program, source),
    };

    let target = match target.parse::<Ipv4Addr>() {
        Ok(ip) => ip,
        Err(_) => panic!("{}: invalid ip address'{}'", program, target),
    };

    route(&target);

    let port = match port.parse::<u16>() {
        Ok(p) => p,
        Err(_) => panic!("{}: invalid port'{}'", program, port),
    };

    let mut buf = [0u8; 24];
    let syn_packet = build_syn_packet(port, &source, &target, &mut buf[..]);

    let (mut tx, _) = match transport::transport_channel(65536, Layer4(Ipv4(IpNextHeaderProtocols::Tcp))) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!("{}: unable to create channel: {}", program, e),
    };

    tx.send_to(syn_packet, IpAddr::V4(target));

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

fn build_syn_packet<'a>(dest: u16, source: &Ipv4Addr,
                    target: &Ipv4Addr, buf: &'a mut [u8]) -> MutableTcpPacket<'a> {
    //setting options
    buf[20] = 0x02; //Kind: Maximum Segment Size (2)
    buf[21] = 0x04; //Length: 4
    buf[22] = 0x05; //*
    buf[23] = 0xb4; //* MSS Value: 1460

    let sequence = rand::thread_rng().gen::<u32>();
    let checksum = rand::thread_rng().gen::<u16>();
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

// fn route(target: &Ipv4Addr) -> (Ipv4Addr, Ipv4Addr) {
fn route(target: &Ipv4Addr) {
    let mut buf = [0u8; 12];
    let identifier = rand::thread_rng().gen::<u16>();
    let mut icmp_request = MutableEchoRequestPacket::new(&mut buf).unwrap();
    icmp_request.set_icmp_type(icmp::IcmpType(8));
    icmp_request.set_identifier(identifier);
    icmp_request.set_sequence_number(1);
    let checksum = icmp::checksum(&IcmpPacket::new(icmp_request.packet()).unwrap());
    icmp_request.set_checksum(checksum);

    let (mut tx, mut rx) = match transport::transport_channel(65536, Layer4(Ipv4(IpNextHeaderProtocols::Icmp))) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!("{}: unable to create channel: {}", "ICMP", e),
    };

    let mut iter = transport::ipv4_packet_iter(&mut rx.clone());
    // tx.send_to(icmp_request, IpAddr::V4(*target)).unwrap();
    loop {
        match iter.next() {
            Ok((packet, addr)) => {
                if let IpAddr::V4(addr) = addr {
                    if addr.eq(target) {
                        let packet = IcmpPacket::new(&packet.packet()).unwrap();
                        if packet.get_icmp_type() == icmp::IcmpType(0) {
                            println!("{}", "received icmp");
                            return
                        }
                    }
                }

            },
            Err(e) => return,
        }
    }
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
