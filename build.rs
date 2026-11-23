use pulldown_cmark::{html, Options, Parser};
use std::{env, fs, io, path::PathBuf};

fn main() -> io::Result<()> {
    println!("cargo:rerun-if-changed=README.md");
    let readme = fs::read_to_string("README.md")?;
    let mut page = String::from(
        r#"<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>fp-tls-server</title>
<style>
body { margin: 0; color: #24292f; font: 1rem/1.7 system-ui, sans-serif; }
main { max-width: 54rem; margin: auto; padding: 1.5rem clamp(1rem, 4vw, 3rem) 4rem; overflow-wrap: anywhere; }
h1, h2 { line-height: 1.3; border-bottom: 1px solid #d1d9e0; padding-bottom: .3em; }
a { color: #0969da; }
pre, code { background: #f4f6f8; border-radius: .25rem; }
code { padding: .1em .25em; }
pre { padding: 1rem; overflow-x: auto; }
pre code { padding: 0; }
table { border-collapse: collapse; }
th, td { border: 1px solid #d1d9e0; padding: .4em .7em; text-align: left; }
</style></head><body><main>
"#,
    );
    html::push_html(&mut page, Parser::new_ext(&readme, Options::ENABLE_TABLES));
    page.push_str("</main></body></html>\n");
    fs::write(
        PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("index.html"),
        page,
    )
}
