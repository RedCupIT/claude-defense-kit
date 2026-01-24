use std::net::TcpStream;
use std::sync::Mutex;
use std::time::Duration;
use tauri::{Emitter, Manager};
use tauri_plugin_shell::process::CommandChild;
use tauri_plugin_shell::ShellExt;

// Global state to hold the server process
struct ServerProcess(Mutex<Option<CommandChild>>);

#[tauri::command]
fn get_server_url(state: tauri::State<'_, ServerState>) -> String {
    let port = state.port.lock().unwrap();
    format!("http://localhost:{}", *port)
}

struct ServerState {
    port: Mutex<u16>,
}

fn find_available_port(start: u16) -> u16 {
    portpicker::pick_unused_port().unwrap_or(start)
}

fn wait_for_server(port: u16, timeout_ms: u64) -> bool {
    let start = std::time::Instant::now();
    let timeout = Duration::from_millis(timeout_ms);
    let addr = format!("127.0.0.1:{}", port);

    while start.elapsed() < timeout {
        if TcpStream::connect(&addr).is_ok() {
            // Give the server a moment to be fully ready
            std::thread::sleep(Duration::from_millis(100));
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            let port = find_available_port(3847);

            // Store port in state
            app.manage(ServerState {
                port: Mutex::new(port),
            });
            app.manage(ServerProcess(Mutex::new(None)));

            // Get the resource directory for data files
            let resource_dir = app
                .path()
                .resource_dir()
                .expect("Failed to get resource directory");
            let data_dir = resource_dir.join("data");

            // Spawn the sidecar server
            let sidecar_command = app
                .shell()
                .sidecar("cdk-server")
                .expect("Failed to create sidecar command")
                .args(["--port", &port.to_string(), "--no-open"])
                .env("CDK_DATA_DIR", data_dir.to_string_lossy().to_string());

            let (mut rx, child) = sidecar_command
                .spawn()
                .expect("Failed to spawn server sidecar");

            // Store the child process for cleanup
            let server_proc = app.state::<ServerProcess>();
            *server_proc.0.lock().unwrap() = Some(child);

            // Handle sidecar output in background
            let app_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                use tauri_plugin_shell::process::CommandEvent;
                while let Some(event) = rx.recv().await {
                    match event {
                        CommandEvent::Stdout(line) => {
                            let line_str = String::from_utf8_lossy(&line);
                            println!("[server] {}", line_str);
                        }
                        CommandEvent::Stderr(line) => {
                            let line_str = String::from_utf8_lossy(&line);
                            eprintln!("[server error] {}", line_str);
                        }
                        CommandEvent::Error(err) => {
                            eprintln!("[server error] {}", err);
                        }
                        CommandEvent::Terminated(status) => {
                            println!("[server] Process terminated with status: {:?}", status);
                            // If server exits unexpectedly, emit event
                            let _ = app_handle.emit("server-terminated", status.code);
                        }
                        _ => {}
                    }
                }
            });

            // Wait for server to be ready (up to 10 seconds)
            let url = format!("http://localhost:{}", port);
            if wait_for_server(port, 10000) {
                println!("Server is ready at {}", url);
            } else {
                eprintln!("Warning: Server may not be ready yet");
            }

            // Navigate the main window to the server URL
            let window = app
                .get_webview_window("main")
                .expect("Failed to get main window");
            window.eval(&format!(r#"window.location.href = "{}";"#, url))?;

            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                // Kill the server process when window closes
                if let Some(server_proc) = window.try_state::<ServerProcess>() {
                    if let Ok(mut proc) = server_proc.0.lock() {
                        if let Some(child) = proc.take() {
                            let _ = child.kill();
                        }
                    }
                }
            }
        })
        .invoke_handler(tauri::generate_handler![get_server_url])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
