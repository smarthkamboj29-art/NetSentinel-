use std::io;
use pnet::datalink;
use pnet::packet::dns::DnsTypes::NXT;
use pnet:: packet::{Packet};
use pnet::packet::ethernet::{EtherTypes,EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{TcpFlags, TcpPacket};
use pnet::packet::udp::UdpPacket;
use pnet::packet::icmp::IcmpPacket;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::collections::{HashMap,HashSet};
use std::net::Ipv4Addr;
use::std::time::{Duration,Instant};


fn main() {
	
	println!("\n\n==========================================");
	println!("     NETWORK PACKET ANALYZER     ");
	println!("==============================================");
	println!("Select protocol to analyze:");
	println!("1. TCP");
	println!("2. UDP");
	println!("3. ICMP");
	println!("4. ALL");
	println!("Enter choice: ");
	
	let mut choice=String::new();
	io::stdin().read_line(&mut choice).expect("failed to take input");	

	let filter = match choice.trim(){
		"1" => "tcp",
		"2"=>"udp",
		"3"=>"icmp",
		"4"=>"all",
		_=>{println!("invalid input"	);
		  return;
	}
	};


	let mut total_packet=0;
	let mut total_bytes=0;
	let mut tcp_packets=0;
	let mut udp_packets=0;
	let mut icmp_packets=0;



    let interface=datalink::interfaces().into_iter()
		.find(|item| item.is_up() && !item.is_loopback());
	
	match interface{
		Some(interface)=>{
			println!("\nnetwork interface : {}",interface.name);
			
			let local_ips:Vec<Ipv4Addr>=interface.ips.iter().filter_map(|ip| match ip.ip(){
										std::net::IpAddr::V4(ipv4)=>Some(ipv4),
										_=>None,
										} )
										.collect();
			println!("\nlocal ip add :");
			for ip in &interface.ips{
				println!("{}", ip.ip());
			}
			
			
			

		      let channel = datalink::channel(&interface,Default::default());
		      match channel {
			    Ok(datalink::Channel::Ethernet(_,mut rx))=>{
			     
				 println!("\n\nreciver created");
				 println!("packet capturing starting...");
				 println!("press ctrl+c to stop the capturing\n");   
			    
				let running = Arc::new(AtomicBool::new(true));
				let r = running.clone();
				ctrlc::set_handler(move|| {
					r.store(false,Ordering::SeqCst)
				 }).expect("error setting ctrl+c handler");
				
				let mut connections= HashMap::new();
				let mut syn_scans:HashMap<Ipv4Addr,HashMap<u16,Instant>>=HashMap::new();
				let mut alerted_syn_scans:HashSet<Ipv4Addr>=HashSet::new();
				let mut syn_results:HashMap<Ipv4Addr,(u16,u16)>=HashMap::new();
				let mut alerts:Vec<String>=Vec::new();
				let mut udp_scans:HashMap<Ipv4Addr,HashMap<u16,Instant>>=HashMap::new();
				let mut alerted_udp_scans:HashSet<Ipv4Addr>=HashSet::new();
				let mut icmp_floods:HashMap<Ipv4Addr,Vec<Instant>>=HashMap::new();
				let mut alerted_icmp_floods:HashSet<Ipv4Addr>=HashSet::new();
				let mut syn_floods: HashMap<(Ipv4Addr, Ipv4Addr, u16), Vec<Instant>> = HashMap::new();
				let mut alerted_syn_floods: HashSet<(Ipv4Addr, Ipv4Addr, u16)> = HashSet::new();
				let mut csv_writer = csv::Writer::from_path("traffic.csv").expect("failed to create CSV file");

			    csv_writer
					     .write_record(["protocol", "source", "destination", "bytes"])
						 .expect("failed to write CSV header");

			    while running.load(Ordering::SeqCst){
			        match rx.next() {
					     Ok(packet)=>{
							total_packet +=1;
							total_bytes +=packet.len();

			    		    //    println!("packet recived : {} bytes", packet.len());
					       if let Some(ethernet)=EthernetPacket::new(packet){
						    if ethernet.get_ethertype()==EtherTypes::Ipv4{
							// println!("revcived ipv4 packet");
						        if let Some(ipv4)=Ipv4Packet::new(ethernet.payload()){
							       match ipv4.get_next_level_protocol(){
										IpNextHeaderProtocols::Tcp=>{
											if filter=="tcp" || filter=="all"{
												tcp_packets +=1;												
												analyse_tcp(&ipv4, packet,&mut connections,&local_ips
																,& mut syn_scans
																,& mut syn_results
															    ,&mut alerts
																,&mut alerted_syn_scans
																,&mut syn_floods
																,&mut alerted_syn_floods
																,&mut csv_writer
																  );
											}	
										}
										IpNextHeaderProtocols::Udp=>{
											if filter=="udp" || filter=="all"{
												udp_packets +=1;
												analyse_udp(&ipv4, packet, &local_ips 
													,&mut udp_scans
													,&mut alerted_udp_scans
													, &mut alerts
												    ,&mut csv_writer
													 );
											}
										}
										IpNextHeaderProtocols::Icmp=>{
											if filter=="icmp" || filter=="all"{
												icmp_packets +=1;
												analyse_icmp(&ipv4,packet,&mut icmp_floods,&mut alerted_icmp_floods,&mut alerts,&mut csv_writer)
											}
										}
										_=>{}
										
								   }

								    
								}
						     	}
							}
						}
						
					Err(err)=>{
					       println!("packet receive error : {}", err);
						}
					}
				}




				
				for (connection,count) in connections{
				//	println!("{:?} -> {} times :", connection , count);

					check_repeated_connection(count,&mut alerts,&connection);

				}
                
				for (ip,(syn_count,rst_count)) in &syn_results{
					if *syn_count>=10 && *rst_count>=5{
							alerts.push(format!("suspicious syn/rst pattern | source : {} | SYN : {} | RST : {}",
										ip,syn_count,rst_count
							));
							
						}
					}
				
                
				println!("\n\n========== ALERTS ==========");

					if alerts.is_empty() {
						    println!("No suspicious activity detected.");
							} else {
    							for alert in &alerts {
    							    println!("[ALERT] {}", alert);
   									 }
					}

				println!("============================");
				
				
				println!("\n========== Statistics ==========");
				println!("total packets : {}", total_packet);
				println!("total bytes   : {}", total_bytes);
				println!("tcp packets   : {}", tcp_packets);
				println!("udp packets   : {}", udp_packets);
				println!("icmp packets  : {}", icmp_packets);
                println!("================================");
				

			}
			Ok(_)=>{
				println!("unsupported channel type");
			}
			Err(err)=>{
				println!("failed to create channel {}",err);
			}	
			}			
			}
		None=>println!("no network interface"),
		}

}


fn analyse_tcp(ipv4:&Ipv4Packet,packet:&[u8],connections:&mut HashMap<(Ipv4Addr,u16,Ipv4Addr,u16),u32>,local_ips:&[Ipv4Addr]
							,syn_scans:&mut HashMap<Ipv4Addr,HashMap<u16,Instant>>	
							,syn_results:&mut HashMap<Ipv4Addr,(u16,u16)>
							,alerts:&mut Vec<String>
							,alerted_syn_scans:&mut HashSet<Ipv4Addr>	
							,syn_floods: &mut HashMap<(Ipv4Addr, Ipv4Addr, u16), Vec<Instant>>
							,alerted_syn_floods: &mut HashSet<(Ipv4Addr, Ipv4Addr, u16)>		
							,csv_writer: &mut csv::Writer<std::fs::File>						){

	if let Some(tcp)=TcpPacket::new(ipv4.payload()){
				csv_writer.write_record([
					"TCP",
					&format!("{}:{}", ipv4.get_source(), tcp.get_source()),
					&format!("{}:{}", ipv4.get_destination(), tcp.get_destination()),
					&packet.len().to_string(),
				]).expect("failed to write TCP record");

				let connection=(
					ipv4.get_source(),
					tcp.get_source(),
					ipv4.get_destination(),
					tcp.get_destination(),
					);
				
				*connections.entry(connection).or_insert(0) +=1;
				
				let direction=get_direction(&ipv4.get_source(),&local_ips);
				
				print!("[TCP] {}:{} -> {}:{} | {} bytes | {} | flags: ",
								ipv4.get_source(),tcp.get_source()
								,ipv4.get_destination(),tcp.get_destination()
								,packet.len(),direction);
							
							 
						    let flags: u8=tcp.get_flags();
							if flags & TcpFlags::SYN !=0{
								print!("SYN ");
								
								let source= ipv4.get_source();
								let destination_port= tcp.get_destination();
								let now=Instant::now();


								let ports=syn_scans.entry(source).or_default();
								ports.insert(destination_port,now);

								ports.retain(|_,timestamp| {
									now.duration_since(*timestamp) <= Duration::from_secs(10)
								});
								
								if ports.len()>=10{
									if alerted_syn_scans.insert(source){
									alerts.push(format!(
										"possible SYN scan | source: {}| unique ports in 10sec: {}",
										source,ports.len()
									));
								    }
									}else{
										alerted_syn_scans.remove(&source);
									
								}
								let entry = syn_results.entry(ipv4.get_source()).or_insert((0,0));
								
								entry.0 +=1;

								let flood_key = (
										ipv4.get_source(),
										ipv4.get_destination(),
										tcp.get_destination(),
									);

									let now = Instant::now();

									let timestamps = syn_floods.entry(flood_key).or_default();

									timestamps.push(now);

									timestamps.retain(|timestamp| {
										now.duration_since(*timestamp) <= Duration::from_secs(10)
									});

									if timestamps.len() >= 100 {
										if alerted_syn_floods.insert(flood_key) {
											alerts.push(format!(
												"possible SYN flood | source: {} | destination: {}:{} | SYN packets in last 10s: {}",
												ipv4.get_source(),
												ipv4.get_destination(),
												tcp.get_destination(),
												timestamps.len()
											));
										}
									} else {
										alerted_syn_floods.remove(&flood_key);
                                    }
																								
									
									}
							if flags & TcpFlags::ACK !=0{
									print!("ACK ");		
									}
							if flags & TcpFlags::FIN !=0{
										print!("FIN ");
									}
							if flags & TcpFlags::RST !=0{
                                    print!("RST ");
								
								let entry = syn_results.entry(ipv4.get_source()).or_insert((0,0));
								entry.1 +=1;


                                    }println!();
			
				
			}	
}

fn analyse_udp(ipv4:&Ipv4Packet,packet:&[u8], local_ips:&[Ipv4Addr],udp_scans: &mut HashMap<Ipv4Addr, HashMap<u16, Instant>>,
    alerted_udp_scans: &mut HashSet<Ipv4Addr>,
    alerts: &mut Vec<String>,
	csv_writer: &mut csv::Writer<std::fs::File>
){
	
	if let Some(udp)=UdpPacket::new(ipv4.payload()){
		        csv_writer.write_record([
					"UDP",
					&format!("{}:{}", ipv4.get_source(), udp.get_source()),
					&format!("{}:{}", ipv4.get_destination(), udp.get_destination()),
					&packet.len().to_string(),
				]).expect("failed to write UDP record");	    
	
		let direction=get_direction(&ipv4.get_destination(),&local_ips);
	
		  println!("[udp] {}:{} -> {}:{} | {} bytes | {}"
	           ,ipv4.get_source(),udp.get_source()
			   ,ipv4.get_destination(),udp.get_destination()
			   ,packet.len()
			   ,direction);
			let source= ipv4.get_source();
			let destination_port= udp.get_destination();
			let now=Instant::now();
		    
			let ports =udp_scans.entry(source).or_default();
			ports.insert(destination_port,now);

			ports.retain(|_, timestamp| {
                now.duration_since(*timestamp) <= Duration::from_secs(10)
                });

			if ports.len()>=10{
				if alerted_udp_scans.insert(source){
					alerts.push(format!(
						"possible UDP scan | source: {} | unique ports in 10sec : {}",
						source,ports.len()
					));
				}
			}else{
				alerted_udp_scans.remove(&source);
			}
	}
}

fn analyse_icmp(ipv4:&Ipv4Packet,packet:&[u8],
	icmp_floods: &mut HashMap<Ipv4Addr, Vec<Instant>>,
    alerted_icmp_floods: &mut HashSet<Ipv4Addr>,
    alerts: &mut Vec<String>,
	csv_writer: &mut csv::Writer<std::fs::File>
){
	
	
	if let Some(icmp)=IcmpPacket::new(ipv4.payload()){
				csv_writer.write_record([
					"ICMP",
					&ipv4.get_source().to_string(),
					&ipv4.get_destination().to_string(),
					&packet.len().to_string(),
				]).expect("failed to write ICMP record");
	
		let source=ipv4.get_source();
		let now=Instant::now();
		let timestamps=icmp_floods.entry(source).or_default();
		timestamps.push(now);

		timestamps.retain(|timestamp|{
			now.duration_since(*timestamp)<=Duration::from_secs(10)
		});

		
		println!("[icmp] {} -> {} | {} bytes | type: {:?}"
	           ,ipv4.get_source(),
			   ipv4.get_destination(),		
			   packet.len(),
			   icmp.get_icmp_type());

		if timestamps.len()>=100{
			if alerted_icmp_floods.insert(source){
				alerts.push(format!(
					"possible ICMP flood | source: {} | packets in last 10s: {}",
                    source,
                    timestamps.len()
				));
			}
		}else{
			alerted_icmp_floods.remove(&source);
		}
    }
}


fn check_repeated_connection(count:u32,alerts:& mut Vec<String>,connection:&(Ipv4Addr,u16,Ipv4Addr,u16)){
	if count>10{
		alerts.push(format!(
			"Repeated connection | {:?} | count : {} times",connection,count
		));
	}
}

fn get_direction(source_ip:&Ipv4Addr,local_ips:&[Ipv4Addr])-> &'static str{
	if local_ips.contains(source_ip){
		"outgoing"
	}else{
		"incoming"
	}
}