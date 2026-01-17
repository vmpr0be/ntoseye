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
    /// Connect to a GDB stub server
    pub fn connect(addr: &str) -> Result<Self, GdbError> {
        let stream = TcpStream::connect(addr)?;

        let mut client = GdbClient {
            stream,
            no_ack_mode: false,
            is_running: false, // NOTE if the user toys with VM via GUI, this value goes bad
        };

        client.force_stop_and_resync()?;

        let _ = client.enable_no_ack_mode();

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
}
