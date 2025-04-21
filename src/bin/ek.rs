use std::process::exit;

use enigmatick_wasm::{load_instance_information, InstanceInformation};
use reedline_repl_rs::clap::{Arg, ArgMatches, Command};
use reedline_repl_rs::{Repl, Result};

async fn hello<T>(args: ArgMatches, _context: &mut T) -> Result<Option<String>> {
    Ok(Some(format!(
        "Hello, {}",
        args.get_one::<String>("who").unwrap()
    )))
}

async fn update_prompt<T>(_context: &mut T) -> Result<Option<String>> {
    Ok(Some("updated".to_string()))
}

async fn server<T>(args: ArgMatches, _context: &mut T) -> Result<Option<String>> {
    load_instance_information(Some(args.get_one::<String>("url").unwrap().to_string())).await;
    Ok(Some("wtfever".to_string()))
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut repl = Repl::new(())
        .with_name("MyApp")
        .with_version("v0.1.0")
        .with_command_async(
            Command::new("hello")
                .arg(Arg::new("who").required(true))
                .about("Greetings!"),
            |args, context| Box::pin(hello(args, context)),
        )
        .with_on_after_command_async(|context| Box::pin(update_prompt(context)))
        .with_command_async(
            Command::new("server")
                .arg(Arg::new("url").required(true))
                .about("Load instance information"),
            |args, context| Box::pin(server(args, context)),
        );
    repl.run_async().await
}
