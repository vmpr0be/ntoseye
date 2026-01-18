use indicatif::{ProgressBar, ProgressStyle};
use nu_ansi_term::{Color, Style};
use reedline::{
    DescriptionMode, Emacs, Highlighter, IdeMenu, KeyCode, KeyModifiers, MenuBuilder,
    ReedlineEvent, ReedlineMenu, StyledText, default_emacs_keybindings,
};
use reedline::{
    Completer, Prompt, PromptEditMode, PromptHistorySearch, PromptHistorySearchStatus, Reedline,
    Signal, Span, Suggestion,
};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use strum::EnumMessage;
use strum::IntoEnumIterator;
use strum_macros::{Display, EnumIter, EnumMessage, EnumString};
use tabled::builder::Builder;
use tabled::settings::object::Rows;
use tabled::settings::{Alignment, Modify, Padding, Panel};

use iced_x86::{
    Code, Decoder, DecoderOptions, Formatter, Instruction, MemorySizeOptions,
    NasmFormatter,
};
use owo_colors::OwoColorize;
use std::{borrow::Cow};

use crate::backend::MemoryOps;
use crate::debugger::{DebuggerArgument, DebuggerContext};
use crate::gdb::GdbClient;
use crate::symbols::{ParsedType, SymbolIndex};
use crate::types::{Value, VirtAddr};

#[derive(Clone)]
pub struct CustomPrompt;
pub static DEFAULT_MULTILINE_INDICATOR: &str = "     ::: ";
impl Prompt for CustomPrompt {
    fn render_prompt_left(&self) -> Cow<'_, str> {
        Cow::Owned("ntoseye>".bright_black().to_string())
    }

    fn render_prompt_right(&self) -> Cow<'_, str> {
        Cow::Owned("".into())
    }

    fn render_prompt_indicator(&self, _edit_mode: PromptEditMode) -> Cow<'_, str> {
        Cow::Owned(" ".to_string())
    }

    fn render_prompt_multiline_indicator(&self) -> Cow<'_, str> {
        Cow::Borrowed(DEFAULT_MULTILINE_INDICATOR)
    }

    fn render_prompt_history_search_indicator(
        &self,
        history_search: PromptHistorySearch,
    ) -> Cow<'_, str> {
        let prefix = match history_search.status {
            PromptHistorySearchStatus::Passing => "",
            PromptHistorySearchStatus::Failing => "failing ",
        };

        Cow::Owned(format!(
            "({}reverse-search: {}) ",
            prefix, history_search.term
        ))
    }
}

struct CustomColorHighlighter;

impl Highlighter for CustomColorHighlighter {
    fn highlight(&self, line: &str, _cursor: usize) -> StyledText {
        let mut styled_text = StyledText::new();
        let input_style = Style::new().fg(Color::LightGray);
        styled_text.push((input_style, line.to_string()));
        styled_text
    }
}

enum CompletionStrategy {
    None,
    Symbol,
    Type,
}

// TODO ps, lm, attach, br, removebr, enablebr, disablebr, continue/g
// TODO allow for expressions to be written
// dexp: display value from evaling expression (via type, either builtin or from pdb)
// dtype: display type definition
// eventually python support maybe?

#[derive(Debug, Clone, Copy, PartialEq, EnumIter, Display, EnumString, EnumMessage)]
#[strum(serialize_all = "kebab-case")]
enum ReplCommand {
    #[strum(
        message = "Display memory as bytes. Command accepts either just a symbol/address, or accepts an optional argument noting either the length or end address. The optional parameter is treated as an address if it's greater than the start address. By default, the optional parameter is 128.\n(usage: db <VirtualAddress or Symbol> [Length or EndAddress])"
    )]
    Db,

    #[strum(message = "Display type definition. Users may optionally supply a memory location, either as a symbol or address, and optionally provide a specific field to be printed.\n(usage: dt <Name> [VirtualAddress or Symbol] [Field])")]
    Dt,

    #[strum(
        message = "Disassemble memory at a symbol or address.\n(usage: disasm <VirtualAddress or Symbol>)"
    )]
    Disasm,

    #[strum(message = "Resume VM execution.\n(usage: continue)")]
    Continue,

    #[strum(
        message = "Display the page table entry (PTE) and page directory entry (PDE) for the specified address.\n(usage: pte <VirtualAddress or Symbol>)"
    )]
    Pte,

    #[strum(message = "List all threads and their RIP values.\n(usage: lt)")]
    Lt,

    #[strum(message = "Exit the application.")]
    Quit,
}

impl ReplCommand {
    pub fn completion_type(&self) -> CompletionStrategy {
        match self {
            Self::Quit => CompletionStrategy::None,
            Self::Pte => CompletionStrategy::Symbol,
            Self::Db => CompletionStrategy::Symbol,
            Self::Disasm => CompletionStrategy::Symbol,
            Self::Lt => CompletionStrategy::None,
            Self::Continue => CompletionStrategy::None,
            Self::Dt => CompletionStrategy::Type,
        }
    }
}

struct MyCompleter {
    symbols: Arc<SymbolIndex>,
    types: Arc<SymbolIndex>,
}

impl Completer for MyCompleter {
    fn complete(&mut self, line: &str, pos: usize) -> Vec<Suggestion> {
        let text_before_cursor = &line[..pos];
        let mut parts = text_before_cursor.split_whitespace();

        let command_str = parts.next().unwrap_or("");
        let is_command_context = !text_before_cursor.contains(' ');

        if is_command_context {
            return ReplCommand::iter()
                .filter_map(|cmd| {
                    let c_str = cmd.to_string();
                    if c_str.starts_with(command_str) {
                        Some(Suggestion {
                            value: c_str,
                            description: cmd.get_message().map(String::from),
                            style: None,
                            extra: None,
                            match_indices: None,
                            span: Span::new(0, pos),
                            append_whitespace: true,
                        })
                    } else {
                        None
                    }
                })
                .collect();
        }

        if let Ok(cmd) = ReplCommand::from_str(command_str) {
            let arg_start = text_before_cursor.rfind(' ').map(|i| i + 1).unwrap_or(0);
            let raw_prefix = &text_before_cursor[arg_start..];

            let prefix = raw_prefix.strip_prefix('*').unwrap_or(raw_prefix);
            let prefix_offset = if raw_prefix.starts_with('*') { 1 } else { 0 };

            match cmd.completion_type() {
                CompletionStrategy::None => return vec![],

                CompletionStrategy::Symbol => {
                    return self
                        .symbols
                        .search(prefix, 1024)
                        .into_iter()
                        .map(|name| Suggestion {
                            value: name,
                            description: Some("Symbol".to_string()),
                            style: None,
                            extra: None,
                            match_indices: None,
                            span: Span::new(arg_start + prefix_offset, pos),
                            append_whitespace: true,
                        })
                        .collect();
                }

                CompletionStrategy::Type => {
                    let mut arg_count = text_before_cursor.split_whitespace().count();
                    if text_before_cursor.ends_with(char::is_whitespace) {
                        arg_count += 1;
                    }

                    if arg_count > 2 {
                        return self
                            .symbols
                            .search(prefix, 1024)
                            .into_iter()
                            .map(|name| Suggestion {
                                value: name,
                                description: Some("Symbol".to_string()),
                                style: None,
                                extra: None,
                                match_indices: None,
                                span: Span::new(arg_start + prefix_offset, pos),
                                append_whitespace: true,
                            })
                            .collect();
                    }

                    return self
                        .types
                        .search(prefix, 1024)
                        .into_iter()
                        .map(|name| Suggestion {
                            value: name,
                            description: Some("Structure".to_string()),
                            style: None,
                            extra: None,
                            match_indices: None,
                            span: Span::new(arg_start + prefix_offset, pos),
                            append_whitespace: true,
                        })
                        .collect();
                }
            }
        }

        vec![]
    }
}

fn error(msg: &str) {
    eprintln!("{} {}", "error:".red(), msg);
}

fn fatal_error(msg: &str) -> ! {
    error(msg);
    std::process::exit(1)
}

macro_rules! error {
    ($($arg:tt)*) => {
        error(&format!($($arg)*))
    };
}

fn hexdump(start_address: VirtAddr, data: &[u8]) {
    for (i, chunk) in data.chunks(16).enumerate() {
        print!("{:08x}  ", start_address + ((i * 16) as u64));

        for byte in chunk {
            print!("{:02x} ", byte);
        }

        for i in chunk.len()..16 {
            print!("   ");
        }

        print!(" ");

        // not the most efficient, FIXME?
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                print!("{}", *byte as char);
            } else {
                print!("{}", ".".bright_black());
            }
        }

        println!("");
    }

    println!("");
}

fn vec_u8_to_u64_le(bytes: Vec<u8>) -> Vec<u64> {
    bytes
        .chunks_exact(8)
        .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()))
        .collect()
}

struct TrackingHighlighter {
    had_content: Arc<AtomicBool>,
}

impl Highlighter for TrackingHighlighter {
    fn highlight(&self, line: &str, _cursor: usize) -> StyledText {
        self.had_content.store(!line.is_empty(), Ordering::Relaxed);

        let mut styled = StyledText::new();
        styled.push((Style::new(), line.to_string()));
        styled
    }
}

pub fn start_repl(debugger: &mut DebuggerContext) -> Result<(), String> {
    let message_data = debugger.get_startup_message_data()?;

    let splash_text = format!(
        "{} {}\n{} Kernel version = {}\n{} Kernel base = {:#x}\n{} PsLoadedModuleList = {:#x}\n",
        "    ⢀⣴⠶⣶⡄⠀⠀⠀⠀".bright_blue(),
        format!(
            "Windows kernel debugger for Linux ({} {})",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        )
        .bright_magenta()
        .bold(),
        "⢀⣴⣧⠀⠸⣿⣀⣸⡇⠀⢨⡦⣄".bright_blue(),
        message_data.build_number,
        "⠘⣿⣿⣄⠀⠈⠛⠉⠀⣠⣾⡿⠋".bright_blue(),
        message_data.base_address,
        "⠀⠀⠈⠛⠿⠶⣶⡶⠿⠟⠉⠀⠀".bright_blue(),
        message_data.loaded_module_list
    );

    println!("{}", splash_text);

    // TODO make this non-fatal
    let mut client = GdbClient::connect("127.0.0.1:1234").map_err(|e| "failed to connect to gdbstub")?;

    let min_completion_width: u16 = 0;
    let max_completion_width: u16 = 50;
    let max_completion_height: u16 = 12;
    let padding: u16 = 0;
    let border: bool = true;
    let cursor_offset: i16 = 0;
    let description_mode: DescriptionMode = DescriptionMode::PreferRight;
    let min_description_width: u16 = 0;
    let max_description_width: u16 = 50;
    let description_offset: u16 = 1;
    let correct_cursor_pos: bool = false;

    let mut ide_menu = IdeMenu::default()
        .with_name("completion_menu")
        .with_min_completion_width(min_completion_width)
        .with_max_completion_width(max_completion_width)
        .with_max_completion_height(max_completion_height)
        .with_padding(padding)
        .with_cursor_offset(cursor_offset)
        .with_description_mode(description_mode)
        .with_min_description_width(min_description_width)
        .with_max_description_width(max_description_width)
        .with_description_offset(description_offset)
        .with_correct_cursor_pos(correct_cursor_pos)
        .with_marker(" ")
        .with_text_style(Style::new().fg(Color::LightGray));

    if border {
        ide_menu = ide_menu.with_default_border();
    }

    let completion_menu = Box::new(ide_menu);

    let mut keybindings = default_emacs_keybindings();
    keybindings.add_binding(
        KeyModifiers::NONE,
        KeyCode::Tab,
        ReedlineEvent::UntilFound(vec![
            ReedlineEvent::Menu("completion_menu".to_string()),
            ReedlineEvent::MenuNext,
        ]),
    );
    keybindings.add_binding(
        KeyModifiers::SHIFT,
        KeyCode::BackTab,
        ReedlineEvent::UntilFound(vec![
            ReedlineEvent::Menu("completion_menu".to_string()),
            ReedlineEvent::MenuPrevious,
        ]),
    );

    let edit_mode = Box::new(Emacs::new(keybindings));

    let completor = Box::new(MyCompleter {
        symbols: debugger
            .symbols
            .symbol_index(debugger.guest.ntoskrnl.guid.unwrap())
            .unwrap(),
        types: debugger
            .symbols
            .types_index(debugger.guest.ntoskrnl.guid.unwrap())
            .unwrap(),
    });

    let had_content = Arc::new(AtomicBool::new(false));
    let highlighter = TrackingHighlighter {
        had_content: Arc::clone(&had_content),
    };

    let mut line_editor = Reedline::create()
        .with_completer(completor)
        .with_menu(ReedlineMenu::EngineCompleter(completion_menu))
        .with_edit_mode(edit_mode)
        .with_highlighter(Box::new(highlighter));
    let prompt = CustomPrompt {};

    loop {
        let sig = line_editor.read_line(&prompt).map_err(|e| e.to_string())?;
        match sig {
            Signal::Success(buffer) => {
                let parts: Vec<&str> = buffer.trim().split_whitespace().collect();
                if let Some(cmd_str) = parts.first() {
                    match ReplCommand::from_str(cmd_str) {
                        Ok(ReplCommand::Quit) => {
                            break;
                        }
                        Ok(ReplCommand::Pte) => {
                            let arg = match parts.get(1) {
                                Some(a) => a,
                                None => {
                                    println!(
                                        "{}\n",
                                        ReplCommand::Pte.get_message().unwrap_or("invalid usage")
                                    );
                                    continue;
                                }
                            };
                            let arg = DebuggerArgument::new(arg);
                            match debugger.pte_traverse(arg) {
                                Ok(result) => {
                                    let mut levels = vec![result.pxe, result.ppe];

                                    if let Some(x) = result.pde {
                                        levels.push(x);
                                    }

                                    if let Some(x) = result.pte {
                                        levels.push(x);
                                    }

                                    let header = format!("VA {:016x}", result.address);
                                    let mut builder = Builder::default();

                                    let row_strings: Vec<String> =
                                        levels.iter().map(|l| l.to_string()).collect();
                                    builder.push_record(row_strings);

                                    let mut table = builder.build();
                                    table
                                        .with(Panel::header(header))
                                        .with(Modify::new(Rows::first()).with(Alignment::center()))
                                        .with(tabled::settings::Style::empty());

                                    println!("{}\n", table);
                                }
                                Err(e) => {
                                    error!("{}\n", e);
                                }
                            }
                        }
                        Ok(ReplCommand::Db) => {
                            let start_address = DebuggerArgument::new(match parts.get(1) {
                                Some(a) => a,
                                None => {
                                    println!(
                                        "{}\n",
                                        ReplCommand::Db.get_message().unwrap_or("invalid usage")
                                    );
                                    continue;
                                }
                            })
                            .resolve(debugger)?;

                            let default_end = format!("{:#x}", start_address.0 + 128);
                            let mut end = DebuggerArgument::new(match parts.get(2) {
                                Some(e) => e,
                                None => &default_end,
                            })
                            .resolve(debugger)?;

                            if end.0 < start_address.0 {
                                end = end + start_address.0;
                            }

                            let mut data: Vec<u8> = vec![0u8; (end.0 - start_address.0) as usize];
                            debugger
                                .get_current_process()
                                .memory(&debugger.kvm)
                                .read_bytes(start_address, &mut data)?;

                            hexdump(start_address, &data);
                        }
                        Ok(ReplCommand::Disasm) => {
                            let start_address = DebuggerArgument::new(match parts.get(1) {
                                Some(a) => a,
                                None => {
                                    println!(
                                        "{}\n",
                                        ReplCommand::Db.get_message().unwrap_or("invalid usage")
                                    );
                                    continue;
                                }
                            })
                            .resolve(debugger)?;

                            let default_end = format!("{:#x}", start_address.0 + 32);
                            let mut end = DebuggerArgument::new(match parts.get(2) {
                                Some(e) => e,
                                None => &default_end,
                            })
                            .resolve(debugger)?;

                            if end.0 < start_address.0 {
                                end = end + start_address.0;
                            }

                            let mut bytes: Vec<u8> = vec![0u8; (end.0 - start_address.0) as usize];
                            debugger
                                .get_current_process()
                                .memory(&debugger.kvm)
                                .read_bytes(start_address, &mut bytes)?;

                            let mut decoder = Decoder::with_ip(
                                64, /* TODO dont hardcode for WOW64 process? */
                                &bytes,
                                start_address.0,
                                DecoderOptions::NONE,
                            );

                            // TODO support other formats?
                            let mut formatter = NasmFormatter::new();
                            let options = formatter.options_mut();
                            options.set_space_after_operand_separator(true);
                            options.set_hex_prefix("0x");
                            options.set_hex_suffix("");
                            options.set_first_operand_char_index(5);
                            options.set_memory_size_options(MemorySizeOptions::Always);
                            options.set_show_branch_size(false);
                            options.set_rip_relative_addresses(true);

                            let mut output = String::new();
                            let mut instruction = Instruction::default();

                            while decoder.can_decode() {
                                decoder.decode_out(&mut instruction);
                                if instruction.code() == Code::INVALID {
                                    continue;
                                }

                                output.clear();
                                formatter.format(&instruction, &mut output);

                                print!("{:016x} ", VirtAddr(instruction.ip()));
                                let start_index = (instruction.ip() - start_address.0) as usize;
                                let instr_bytes =
                                    &bytes[start_index..start_index + instruction.len()];
                                for b in instr_bytes.iter() {
                                    print!("{:02x}", Value(b));
                                }
                                if instr_bytes.len() < 12 {
                                    for _ in 0..12 - instr_bytes.len() {
                                        print!("  ");
                                    }
                                }
                                print!(" {}", output);

                                if instruction.is_ip_rel_memory_operand() {
                                    let target_address = instruction.ip_rel_memory_address();
                                    print!(
                                        "{}",
                                        format!(" ; 0x{:X}", target_address).bright_black()
                                    );
                                }

                                println!("");
                            }
                            println!("");
                        }
                        Ok(ReplCommand::Lt) => {
                            if client.is_running {
                                error!(
                                    "VM is running"
                                );
                                continue;
                            }

                            let pb = ProgressBar::new_spinner();
                            pb.set_style(
                                ProgressStyle::default_spinner()
                                    .template("{spinner:.black.bright} {msg}")
                                    .unwrap(),
                            );

                            pb.set_message(format!(
                                "{}",
                                owo_colors::OwoColorize::bright_black(&"Waiting on GDB...")
                            ));
                            pb.enable_steady_tick(Duration::from_millis(100));

                            let original_thread = client
                                .get_stopped_thread_id()
                                .map_err(|e| format!("{:?}", e))?;
                            let threads =
                                client.get_thread_list().map_err(|e| format!("{:?}", e))?;

                            let mut thread_data: Vec<(String, String, String)> = Vec::new();

                            for thread in &threads {
                                client
                                    .set_current_thread(thread)
                                    .map_err(|e| format!("{:?}", e))?;
                                // let rip =
                                //   client.read_register_u64(16).map_err(|e| format!("{:?}", e))?;
                                let registers = vec_u8_to_u64_le(
                                    client.read_registers().map_err(|e| format!("{:?}", e))?,
                                );
                                let rip = registers[16];
                                // let cr3 = u64::from_le_bytes(registers[316..316+8].try_into().unwrap());

                                let attempt = debugger.get_current_process().closest_symbol(&debugger.symbols, VirtAddr(rip));

                                let symbol = match attempt {
                                    Ok((symbol, offset)) => format!("{}+{:#x}", symbol, offset),
                                    Err(e) => e
                                };

                                thread_data
                                    .push((thread.clone(), format!("{:#018x}", VirtAddr(rip)), symbol));
                            }

                            client
                                .set_current_thread(&original_thread)
                                .map_err(|e| format!("{:?}", e))?;

                            let mut builder = Builder::default();
                            builder.push_record(vec!["Thread  ", &format!("{:-20}", "RIP"), "Symbol"]);
                            for (tid, rip, sym) in thread_data {
                                builder.push_record(vec![tid, rip, sym]);
                            }

                            pb.finish_and_clear();

                            let mut table = builder.build();
                            table
                                .with(tabled::settings::Style::empty())
                                .with(Padding::zero());
                            println!("{}\n", table);
                        }
                        Ok(ReplCommand::Continue) => {
                            if client.is_running {
                                error!("VM is running");
                                continue;
                            }
                            if let Err(e) = client.continue_execution() {
                                error!("failed to continue: {:?}", e);
                            }
                        }
                        Ok(ReplCommand::Dt) => {
                            let arg = match parts.get(1) {
                                Some(a) => a,
                                None => {
                                    println!("{}\n", ReplCommand::Dt.get_message().unwrap());
                                    continue;
                                }
                            };

                            let mut address = DebuggerArgument::new(match parts.get(2) {
                                Some(e) => e,
                                None => "0",
                            })
                            .resolve(debugger)?;

                            let field_name = parts.get(3);

                            let process = debugger.get_current_process();
                            match process.class(&debugger.symbols, arg) {
                                Ok(type_info) => {
                                    let mut builder = Builder::default();
                                    builder.push_record(vec![format!(
                                        "{} ({} bytes)",
                                        type_info.name,
                                        Value(type_info.size)
                                    )]);

                                    let mut sorted_fields: Vec<_> =
                                        type_info.fields.iter().collect();
                                    sorted_fields.sort_by_key(|(_, info)| {
                                        let bitfield_pos = match &info.type_data {
                                            ParsedType::Bitfield { pos, .. } => *pos,
                                            _ => 0,
                                        };
                                        (info.offset, bitfield_pos)
                                    });

                                    for (name, info) in sorted_fields {
                                        let value = if address.0 != 0 {
                                            let mem = debugger
                                                .get_current_process()
                                                .memory(&debugger.kvm);
                                            match &info.type_data {
                                                ParsedType::Primitive(p) => {
                                                    if p.contains("*") || p.contains("LONGLONG") {
                                                        let val: u64 =
                                                            mem.read(address + info.offset.into())?;
                                                        format!(" = {:#x}", Value(val))
                                                    } else if p.contains("LONG") {
                                                        let val: u32 =
                                                            mem.read(address + info.offset.into())?;
                                                        format!(" = {:#x}", Value(val))
                                                    } else if p.contains("SHORT")
                                                        || p.contains("WCHAR")
                                                    {
                                                        let val: u16 =
                                                            mem.read(address + info.offset.into())?;
                                                        format!(" = {:#x}", Value(val))
                                                    } else if p.contains("CHAR") {
                                                        let val: u8 =
                                                            mem.read(address + info.offset.into())?;
                                                        format!(" = {:#x}", Value(val))
                                                    } else {
                                                        "".into()
                                                    }
                                                }
                                                ParsedType::Pointer(_) => {
                                                    let val: u64 =
                                                        mem.read(address + info.offset.into())?;
                                                    format!(" = {:#x}", Value(val))
                                                }
                                                ParsedType::Bitfield {
                                                    underlying,
                                                    pos,
                                                    len,
                                                } => {
                                                    let val: u64 =
                                                        mem.read(address + info.offset.into())?;
                                                    let val = (val >> pos) & ((1u64 << len) - 1);

                                                    if *len == 1 {
                                                        if val == 1 {
                                                            format!(" = {}", "Y".green())
                                                        } else {
                                                            format!(" = {}", "N".red())
                                                        }
                                                    } else {
                                                        format!(" = {}", Value(val))
                                                    }
                                                }
                                                _ => "".into(),
                                            }
                                        } else {
                                            "".into()
                                        };

                                        if field_name.is_none() || field_name.unwrap() == name {
                                            builder.push_record(vec![
                                                format!(
                                                    "  + {:#06x} {:-12}",
                                                    VirtAddr(info.offset.into()),
                                                    name
                                                ),
                                                format!("  : {}", info.type_data.green()),
                                                format!("  {}", value),
                                            ]);
                                        }
                                    }

                                    let mut table = builder.build();
                                    table
                                        .with(tabled::settings::Style::empty())
                                        .with(Padding::zero());
                                    println!("{}\n", table);
                                }
                                Err(e) => {
                                    error!("failed to get type information: {}\n", e);
                                }
                            }
                        }
                        Err(_) => {
                            println!(
                                "unknown command: '{}' (try pressing tab to see available commands)\n",
                                cmd_str
                            );
                        }
                    }
                }
            }
            Signal::CtrlD => {
                break;
            }
            Signal::CtrlC => {
                if had_content.load(Ordering::Relaxed) {
                    had_content.store(false, Ordering::Relaxed);
                    continue;
                }

                if client.is_running {
                    if let Err(e) = client.interrupt() {
                        error!("failed to interrupt: {:?}", e);
                    }
                } else {
                    error!("VM is already paused");
                }
            }
        }
    }

    Ok(())
}
