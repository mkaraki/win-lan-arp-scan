use std::ffi::c_void;
use std::process::exit;
use std::str::Chars;
use windows::w;
use windows::Win32::NetworkManagement::IpHelper::*;
use windows::Win32::Foundation::*;
use std::env;

fn main() {
    let args:Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Usage: win-lan-arp-scan.exe <network-address>/<cidr>");
        exit(1);
    }
    let range_addr = get_address_u32range(args[1].as_str());

    let suppress_notfound = true;

    let source_addr: u32 = 0;

    for sec1 in range_addr[0][0]..range_addr[1][0]+1 {
        for sec2 in range_addr[0][1]..range_addr[1][1]+1 {
            for sec3 in range_addr[0][2]..range_addr[1][2]+1 {
                for sec4 in range_addr[0][3]..range_addr[1][3]+1 {
                    let target_addr: u32 =
                        ((sec1 as u32) << 0) +
                            ((sec2 as u32) << 8) +
                            ((sec3 as u32) << 16) +
                            ((sec4 as u32) << 24);

                    let (detected_mac_addr, result) = send_arp(target_addr, source_addr);

                    let w32result = WIN32_ERROR(result);
                    match w32result {
                        NO_ERROR => {
                            print!("{}.{}.{}.{}: ", sec1, sec2, sec3, sec4);
                            print_mac_addr(detected_mac_addr)
                        },
                        ERROR_BAD_NET_NAME | ERROR_GEN_FAILURE => {
                            if !suppress_notfound {
                                print!("{}.{}.{}.{}: ", sec1, sec2, sec3, sec4);
                                println!("Not found")
                            }
                        },
                        ERROR_NOT_FOUND => { println!("Invalid source address"); exit(2);},
                        ERROR_NOT_SUPPORTED => {println!("This device not support ARP"); exit(3);},
                        // Above: Make own list
                        ERROR_NETWORK_UNREACHABLE => { println!("Network unreachable"); exit(4);},
                        _ => { println!("Unknown error: {}", result); exit(5)},
                    }
                }
            }
        }
    }
}

fn get_address_u32range(original_address_string:&str) -> [[u8; 4]; 2]
{
    let mut user_provided_address:[u8; 5] = [0, 0, 0, 0, 0];

    let mut editing_section = 0;
    let mut original_address_string_chars: Vec<char> = original_address_string.chars().collect();
    for i in 0..original_address_string.len() {
        let char = original_address_string_chars[i];
        match char {
            '0'|'1'|'2'|'3'|'4'|'5'|'6'|'7'|'8'|'9' => {
                user_provided_address[editing_section] *= 10;
                user_provided_address[editing_section] += (char as u8) - 0x30;
            },
            '.'|'/' => {
                editing_section += 1;
            },
            _ => {},
        }
    }

    if user_provided_address[4] == 0 || user_provided_address[4] >= 32 {
        return [
            [
                user_provided_address[0],
                user_provided_address[1],
                user_provided_address[2],
                user_provided_address[3],
            ],
            [
                user_provided_address[0],
                user_provided_address[1],
                user_provided_address[2],
                user_provided_address[3],
            ]
        ];
    }

    let mask:u32 = 0xffffffff << (32 - user_provided_address[4]);

    let mut network_addr:u32 = 0;
    network_addr = (network_addr + (user_provided_address[0] as u32)) << 8;
    network_addr = (network_addr + (user_provided_address[1] as u32)) << 8;
    network_addr = (network_addr + (user_provided_address[2] as u32)) << 8;
    network_addr = (network_addr + (user_provided_address[3] as u32));
    network_addr = network_addr & mask;
    let broadcast_addr:u32 = network_addr | !mask;

    let start_address:[u8; 4] = [
        (network_addr >> 24) as u8,
        (network_addr >> 16) as u8,
        (network_addr >> 8) as u8,
        (network_addr + 1) as u8,
    ];

    let end_address:[u8; 4] = [
        (broadcast_addr >> 24) as u8,
        (broadcast_addr >> 16) as u8,
        (broadcast_addr >> 8) as u8,
        (broadcast_addr - 1) as u8,
    ];

    return [start_address, end_address];
}

fn send_arp(target_address:u32, source_address:u32) -> (Vec<u32>, u32) {
    unsafe {
        let mut detected_mac_addr:Vec<u32> = vec![0, 0];
        let mut buffer_size:Vec<u32> = vec![6];
        let result:u32 = SendARP(
            target_address,
            source_address,
            detected_mac_addr.as_mut_ptr() as *mut c_void,
            buffer_size.as_mut_ptr() as *mut u32
        );

        return (detected_mac_addr, result);
    }
}

fn print_mac_addr(mut win_api_mac_addr:Vec<u32>) {
    if win_api_mac_addr.len() != 2 {
        return;
    }

    for i in 0..2 {
        let value = win_api_mac_addr[i];
        for j in 0..4 {
            if i == 1 && j == 2 {
                break;
            }
            let section_value = value >> (8 * j) << 24 >> 24;
            print!("{:02x}", section_value);
            if i != 1 || j == 0 {
                print!(":");
            }
        }
    }
    println!("\u{08}");
}