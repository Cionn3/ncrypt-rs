#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release

pub mod gui;
pub mod app;

use eframe::egui::ViewportBuilder;
use app::NCryptApp;

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: ViewportBuilder::default()
            .with_decorations(false) // Hide the OS-specific "chrome" around the window
            .with_inner_size([860.0, 500.0])
            .with_min_inner_size([860.0, 500.0])
            .with_transparent(true), // To have rounded corners we need transparency
        ..Default::default()
    };
    eframe::run_native(
        "nCrypt",
        options,
        Box::new(|cc| { Ok(Box::new(NCryptApp::new(cc))) })
    )
}