#![windows_subsystem = "windows"]

use std::env;
use std::fs::File;
use std::process::{Child, Command, Stdio};

use tao::{
    event::{Event, StartCause, WindowEvent},
    event_loop::{ControlFlow, EventLoop},
    window::WindowBuilder,
};
use wry::WebViewBuilder;

const UI_URL: &str = "http://127.0.0.1:3000";

fn application_directory() -> std::io::Result<std::path::PathBuf> {
    env::current_exe()?
        .parent()
        .map(std::path::Path::to_path_buf)
        .ok_or_else(|| std::io::Error::other("The launcher executable has no parent directory."))
}

fn start_application(app_dir: &std::path::Path) -> std::io::Result<Child> {
    let bundled_node = app_dir.join("node.exe");
    let node_executable = env::var("NEXUS_NODE_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            if bundled_node.is_file() {
                bundled_node
            } else {
                std::path::PathBuf::from("node")
            }
        });

    let log_path = app_dir.join("nexus-desktop.log");
    let log_file = File::create(log_path)?;
    let error_log = log_file.try_clone()?;

    Command::new(node_executable)
        .arg("p2p.js")
        .current_dir(app_dir)
        .env("NEXUS_DESKTOP_MODE", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(error_log))
        .spawn()
}

fn wait_for_ui() -> bool {
    for _ in 0..50 {
        if std::net::TcpStream::connect(("127.0.0.1", 3000)).is_ok() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    false
}

fn main() {
    let app_dir = match application_directory() {
        Ok(directory) => directory,
        Err(error) => {
            eprintln!("Unable to locate the application directory: {error}");
            return;
        }
    };

    let mut child = match start_application(&app_dir) {
        Ok(child) => child,
        Err(error) => {
            eprintln!("Unable to start Node.js. Install Node.js or set NEXUS_NODE_PATH: {error}");
            return;
        }
    };

    if !wait_for_ui() {
        eprintln!("The local Nexus Share UI did not start at {UI_URL}.");
    }

    let event_loop = EventLoop::new();
    let window = match WindowBuilder::new().with_title("Nexus Share").build(&event_loop) {
        Ok(window) => window,
        Err(error) => {
            eprintln!("Unable to create the application window: {error}");
            let _ = child.kill();
            return;
        }
    };

    let _webview = match WebViewBuilder::new().with_url(UI_URL).build(&window) {
        Ok(webview) => webview,
        Err(error) => {
            eprintln!("Unable to create the web view: {error}");
            let _ = child.kill();
            return;
        }
    };

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;

        match event {
            Event::NewEvents(StartCause::Init) => {}
            Event::WindowEvent { event: WindowEvent::CloseRequested, .. } => {
                let _ = child.kill();
                *control_flow = ControlFlow::Exit;
            }
            _ => {}
        }
    });
}
