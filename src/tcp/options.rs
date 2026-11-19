#[derive(Default)]
pub(super) struct Options {
    pub names: Vec<String>,
    pub layout: Vec<String>,
    pub mss: u16,
    pub scale: Option<u8>,
    pub sack_ok: bool,
    pub timestamps: bool,
    pub ts_zero: bool,
    pub echo_nonzero: bool,
    pub padding_nonzero: bool,
    pub bad: bool,
}

impl Options {
    // Fixed-size options advance by their expected wire size, including when
    // their own length byte is wrong. This affects the rest of the p0f layout.
    pub fn parse(mut raw: &[u8]) -> Self {
        let mut opts = Self::default();
        while let Some(&kind) = raw.first() {
            if opts.layout.len() == 24 {
                opts.bad = true;
                break;
            }
            let (name, symbol) = match kind {
                0 => ("eol".into(), format!("eol+{}", raw.len() - 1)),
                1 => ("nop".into(), "nop".into()),
                2 => ("mss".into(), "mss".into()),
                3 => ("wscale".into(), "ws".into()),
                4 => ("sackOK".into(), "sok".into()),
                5 => ("sack".into(), "sack".into()),
                8 => ("timestamp".into(), "ts".into()),
                _ => (format!("unknown-{kind}"), format!("?{kind}")),
            };
            opts.names.push(name);
            opts.layout.push(symbol);
            let size = match kind {
                0 => {
                    opts.padding_nonzero = raw[1..].iter().any(|&byte| byte != 0);
                    break;
                }
                1 => 1,
                2 => 4,
                3 => 3,
                4 => {
                    opts.sack_ok = true;
                    2
                }
                8 => {
                    opts.timestamps = true;
                    10
                }
                _ => {
                    let size = raw.get(1).copied().unwrap_or(0) as usize;
                    let valid = if kind == 5 { 10..=34 } else { 2..=40 };
                    if !valid.contains(&size) {
                        opts.bad = true;
                        break;
                    }
                    size
                }
            };
            if raw.len() < size {
                opts.bad = true;
                break;
            }
            if kind != 1 && usize::from(raw[1]) != size {
                opts.bad = true;
            }
            match kind {
                2 => opts.mss = u16::from_be_bytes([raw[2], raw[3]]),
                3 => opts.scale = Some(raw[2]),
                8 => {
                    opts.ts_zero = raw[2..6] == [0; 4];
                    opts.echo_nonzero = raw[6..10] != [0; 4];
                }
                _ => {}
            }
            raw = &raw[size..];
        }
        opts
    }
}
