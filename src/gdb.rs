use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

#[derive(Debug)]
pub enum GdbError {
    Io(io::Error),
    Protocol(String),
    NotSupported,
}

#[derive(Debug, Clone)]
pub struct RegisterInfo {
    pub name: String,
    pub offset: usize,
    pub size: usize,
    pub regnum: usize,
}

#[derive(Debug, Default)]
pub struct RegisterMap {
    by_name: HashMap<String, RegisterInfo>,
    ordered: Vec<RegisterInfo>,
}

impl RegisterMap {
    // pub fn get(&self, name: &str) -> Option<&RegisterInfo> {
    //     self.by_name.get(name)
    // }

    // pub fn get_range(&self, name: &str) -> Option<std::ops::Range<usize>> {
    //     self.by_name.get(name).map(|r| r.offset..r.offset + r.size)
    // }

    pub fn read_u64(&self, name: &str, data: &[u8]) -> Option<u64> {
        let info = self.by_name.get(name)?;
        if info.offset + info.size > data.len() {
            return None;
        }
        let slice = &data[info.offset..info.offset + info.size];

        let mut buf = [0u8; 8];
        let copy_len = slice.len().min(8);
        buf[..copy_len].copy_from_slice(&slice[..copy_len]);
        Some(u64::from_le_bytes(buf))
    }

    // pub fn iter(&self) -> impl Iterator<Item = &RegisterInfo> {
    //     self.ordered.iter()
    // }

    // pub fn is_empty(&self) -> bool {
    //     self.ordered.is_empty()
    // }

    fn parse_target_xml(xml: &str) -> Self {
        let mut map = RegisterMap::default();
        let mut current_offset: usize = 0;
        let mut next_regnum: Option<usize> = None;

        let xml = Self::strip_xml_comments(xml);

        for line in xml.lines() {
            let line = line.trim();
            if !line.starts_with("<reg ") {
                continue;
            }

            let name = Self::extract_attr(line, "name");
            let bitsize = Self::extract_attr(line, "bitsize");
            let explicit_regnum = Self::extract_attr(line, "regnum");

            if let (Some(name), Some(bitsize)) = (name, bitsize) {
                let size_bits: usize = bitsize.parse().unwrap_or(0);
                let size_bytes = size_bits / 8;

                let regnum: usize = if let Some(explicit) = explicit_regnum.and_then(|s| s.parse().ok()) {
                    next_regnum = Some(explicit + 1);
                    explicit
                } else {
                    let num = next_regnum.unwrap_or(0);
                    next_regnum = Some(num + 1);
                    num
                };

                let reg = RegisterInfo {
                    name: name.to_string(),
                    offset: current_offset,
                    size: size_bytes,
                    regnum,
                };

                current_offset += size_bytes;
                map.by_name.insert(reg.name.clone(), reg.clone());
                map.ordered.push(reg);
            }
        }

        map
    }

    fn strip_xml_comments(xml: &str) -> String {
        let mut result = xml.to_string();
        while let Some(start) = result.find("<!--") {
            if let Some(end_offset) = result[start..].find("-->") {
                let end = start + end_offset + 3; // +3 for "-->"
                result = format!("{}{}", &result[..start], &result[end..]);
            } else {
                break;
            }
        }
        result
    }

    fn extract_attr<'a>(element: &'a str, attr: &str) -> Option<&'a str> {
        let pattern = format!("{}=\"", attr);
        let start = element.find(&pattern)?;
        let value_start = start + pattern.len();
        let rest = &element[value_start..];
        let end = rest.find('"')?;
        Some(&rest[..end])
    }
}

impl From<io::Error> for GdbError {
    fn from(err: io::Error) -> Self {
        GdbError::Io(err)
    }
}

pub struct GdbClient {
    stream: TcpStream,
    no_ack_mode: bool,
    pub is_running: bool,
}

impl GdbClient {
    pub fn connect(addr: &str) -> Result<Self, GdbError> {
        let stream = TcpStream::connect(addr)?;

        let mut client = GdbClient {
            stream,
            no_ack_mode: false,
            is_running: false, // NOTE if the user toys with VM via GUI, this value goes bad
        };

        client.force_stop_and_resync()?;

        let _ = client.send_packet("qSupported:multiprocess+;swbreak+;hwbreak+;qRelocInsn+;vContSupported+")?;

        let _ = client.enable_no_ack_mode();

        let _ = client.send_packet("?")?;

        Ok(client)
    }

    fn force_stop_and_resync(&mut self) -> Result<(), GdbError> {
        self.stream
            .set_read_timeout(Some(Duration::from_millis(100)))?;

        self.stream.write_all(&[0x03])?;
        self.stream.flush()?;

        loop {
            match self.read_packet() {
                Ok(_pkt) => {}
                Err(_) => {
                    break;
                }
            }
        }

        self.stream.set_read_timeout(None)?;

        self.is_running = false;

        Ok(())
    }

    pub fn send_packet(&mut self, data: &str) -> Result<String, GdbError> {
        let checksum: u8 = data.bytes().fold(0u8, |acc, b| acc.wrapping_add(b));

        let packet = format!("${}#{:02x}", data, checksum);

        self.stream.write_all(packet.as_bytes())?;
        self.stream.flush()?;

        self.read_packet()
    }

    fn read_packet(&mut self) -> Result<String, GdbError> {
        let mut buf = [0u8; 1];
        let mut response = String::new();

        loop {
            self.stream.read_exact(&mut buf)?;
            if buf[0] == b'$' {
                break;
            }
            if buf[0] == b'+' || buf[0] == b'-' {
                continue;
            }
        }

        loop {
            self.stream.read_exact(&mut buf)?;
            if buf[0] == b'#' {
                break;
            }
            response.push(buf[0] as char);
        }

        let mut checksum_buf = [0u8; 2];
        self.stream.read_exact(&mut checksum_buf)?;

        if !self.no_ack_mode {
            self.stream.write_all(b"+")?;
            self.stream.flush()?;
        }

        Ok(response)
    }

    fn enable_no_ack_mode(&mut self) -> Result<(), GdbError> {
        let response = self.send_packet("QStartNoAckMode")?;
        if response == "OK" {
            self.no_ack_mode = true;
            Ok(())
        } else {
            Err(GdbError::NotSupported)
        }
    }

    pub fn query_halt_reason(&mut self) -> Result<String, GdbError> {
        self.send_packet("?")
    }

    pub fn set_breakpoint(&mut self, addr: u64, kind: u32) -> Result<(), GdbError> {
        let response = self.send_packet(&format!("Z0,{:x},{:x}", addr, kind))?;
        if response == "OK" || response.is_empty() {
            Ok(())
        } else if response.starts_with('E') {
            Err(GdbError::Protocol(format!(
                "failed to set breakpoint: {}",
                response
            )))
        } else {
            Err(GdbError::NotSupported)
        }
    }

    pub fn remove_breakpoint(&mut self, addr: u64, kind: u32) -> Result<(), GdbError> {
        let response = self.send_packet(&format!("z0,{:x},{:x}", addr, kind))?;
        if response == "OK" || response.is_empty() {
            Ok(())
        } else if response.starts_with('E') {
            Err(GdbError::Protocol(format!(
                "failed to remove breakpoint: {}",
                response
            )))
        } else {
            Err(GdbError::NotSupported)
        }
    }

    pub fn set_hardware_breakpoint(&mut self, addr: u64, kind: u32) -> Result<(), GdbError> {
        let response = self.send_packet(&format!("Z1,{:x},{:x}", addr, kind))?;
        if response == "OK" || response.is_empty() {
            Ok(())
        } else if response.starts_with('E') {
            Err(GdbError::Protocol(format!(
                "failed to set hardware breakpoint: {}",
                response
            )))
        } else {
            Err(GdbError::NotSupported)
        }
    }

    pub fn remove_hardware_breakpoint(&mut self, addr: u64, kind: u32) -> Result<(), GdbError> {
        let response = self.send_packet(&format!("z1,{:x},{:x}", addr, kind))?;
        if response == "OK" || response.is_empty() {
            Ok(())
        } else if response.starts_with('E') {
            Err(GdbError::Protocol(format!(
                "failed to remove hardware breakpoint: {}",
                response
            )))
        } else {
            Err(GdbError::NotSupported)
        }
    }

    pub fn read_registers(&mut self) -> Result<Vec<u8>, GdbError> {
        let response = self.send_packet("g")?;

        if response.starts_with('E') {
            return Err(GdbError::Protocol(format!(
                "failed to read registers: {}",
                response
            )));
        }

        let bytes: Result<Vec<u8>, _> = (0..response.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&response[i..i + 2], 16))
            .collect();

        bytes.map_err(|_| GdbError::Protocol("invalid hex in register data".to_string()))
    }

    pub fn write_registers(&mut self, data: &[u8]) -> Result<(), GdbError> {
        let hex_data: String = data.iter().map(|b| format!("{:02x}", b)).collect();

        let response = self.send_packet(&format!("G{}", hex_data))?;

        if response == "OK" {
            Ok(())
        } else {
            Err(GdbError::Protocol(format!(
                "failed to write registers: {}",
                response
            )))
        }
    }

    fn send_command_no_reply(&mut self, data: &str) -> Result<(), GdbError> {
        let checksum: u8 = data.bytes().fold(0u8, |acc, b| acc.wrapping_add(b));
        let packet = format!("${}#{:02x}", data, checksum);

        self.stream.write_all(packet.as_bytes())?;
        self.stream.flush()?;

        // In no-ack mode, no response expected immediately
        // In ack mode, read the ACK
        if !self.no_ack_mode {
            let mut buf = [0u8; 1];
            self.stream.read_exact(&mut buf)?;
            if buf[0] != b'+' {
                return Err(GdbError::Protocol("expected ACK".to_string()));
            }
        }

        Ok(())
    }

    pub fn continue_execution(&mut self) -> Result<(), GdbError> {
        self.send_command_no_reply("c")?;
        self.is_running = true;
        Ok(())
    }

    pub fn continue_at(&mut self, addr: u64) -> Result<(), GdbError> {
        self.send_command_no_reply(&format!("c{:x}", addr))
    }

    pub fn step(&mut self) -> Result<(), GdbError> {
        self.send_command_no_reply("s")?;
        self.is_running = true;
        Ok(())
    }

    pub fn step_at(&mut self, addr: u64) -> Result<(), GdbError> {
        self.send_command_no_reply(&format!("s{:x}", addr))?;
        self.is_running = true;
        Ok(())
    }

    pub fn step_and_wait(&mut self) -> Result<String, GdbError> {
        self.step()?;
        self.wait_for_stop()
    }

    pub fn wait_for_stop(&mut self) -> Result<String, GdbError> {
        if !self.is_running {
            return self.query_halt_reason();
        }

        let response = self.read_packet()?;
        self.is_running = false;
        Ok(response)
    }

    pub fn interrupt(&mut self) -> Result<(), GdbError> {
        if !self.is_running {
            return Ok(());
        }

        self.stream.write_all(&[0x03])?;
        self.stream.flush()?;

        let _ = self.read_packet()?;

        self.is_running = false;

        Ok(())
    }

    pub fn get_thread_list(&mut self) -> Result<Vec<String>, GdbError> {
        let mut threads = Vec::new();
        let mut response = self.send_packet("qfThreadInfo")?;

        loop {
            if response == "l" {
                break;
            }

            if response.starts_with('m') {
                let list = &response[1..];
                for id in list.split(',') {
                    if !id.is_empty() {
                        threads.push(id.to_string());
                    }
                }
            }

            response = self.send_packet("qsThreadInfo")?;
        }

        Ok(threads)
    }

    pub fn set_current_thread(&mut self, thread_id: &str) -> Result<(), GdbError> {
        let resp_g = self.send_packet(&format!("Hg{}", thread_id))?;
        if resp_g != "OK" {
            return Err(GdbError::Protocol(format!(
                "failed to set general thread: {}",
                resp_g
            )));
        }

        let resp_c = self.send_packet(&format!("Hc{}", thread_id))?;
        if resp_c != "OK" {
            return Err(GdbError::Protocol(format!(
                "failed to set control thread: {}",
                resp_c
            )));
        }

        Ok(())
    }

    pub fn get_stopped_thread_id(&mut self) -> Result<String, GdbError> {
        let response = self.send_packet("?")?;

        if response.starts_with('T') {
            if let Some(start) = response.find("thread:") {
                let remainder = &response[start + 7..];
                if let Some(end) = remainder.find(';') {
                    return Ok(remainder[0..end].to_string());
                }
            }
        }

        Err(GdbError::Protocol(
            "could not determine thread from stop reply".into(),
        ))
    }

    pub fn get_register_map(&mut self) -> Result<RegisterMap, GdbError> {
        let mut xml = String::new();
        let mut offset = 0;

        loop {
            let query = format!("qXfer:features:read:target.xml:{:x},fff", offset);
            let response = self.send_packet(&query)?;

            if response.is_empty() {
                return Err(GdbError::NotSupported);
            }

            let (marker, data) = response.split_at(1);
            xml.push_str(data);
            offset += data.len();

            match marker {
                "l" => break, // last chunk
                "m" => continue, // more data
                _ => {
                    return Err(GdbError::Protocol(format!(
                        "unexpected qXfer response: {}",
                        response
                    )))
                }
            }
        }

        let full_xml = self.resolve_xml_includes(&xml)?;

        Ok(RegisterMap::parse_target_xml(&full_xml))
    }

    fn resolve_xml_includes(&mut self, xml: &str) -> Result<String, GdbError> {
        let mut result = xml.to_string();

        while let Some(start) = result.find("<xi:include") {
            let end = match result[start..].find("/>") {
                Some(e) => start + e + 2,
                None => break,
            };

            let element = &result[start..end];
            let href = RegisterMap::extract_attr(element, "href");

            if let Some(filename) = href {
                // fetch the included file
                let included_xml = self.fetch_feature_file(filename)?;
                result = format!("{}{}{}", &result[..start], included_xml, &result[end..]);
            } else {
                // no href, just remove the include element
                result = format!("{}{}", &result[..start], &result[end..]);
            }
        }

        Ok(result)
    }

    fn fetch_feature_file(&mut self, filename: &str) -> Result<String, GdbError> {
        let mut xml = String::new();
        let mut offset = 0;

        loop {
            let query = format!("qXfer:features:read:{}:{:x},fff", filename, offset);
            let response = self.send_packet(&query)?;

            if response.is_empty() {
                return Err(GdbError::NotSupported);
            }

            let (marker, data) = response.split_at(1);
            xml.push_str(data);
            offset += data.len();

            match marker {
                "l" => break,
                "m" => continue,
                _ => {
                    return Err(GdbError::Protocol(format!(
                        "unexpected qXfer response for {}: {}",
                        filename, response
                    )))
                }
            }
        }

        Ok(xml)
    }
}
