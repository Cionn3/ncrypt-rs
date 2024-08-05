pub mod gui;

use gui::app::NCryptApp;

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default().with_inner_size([1024.0, 500.0]),
        ..Default::default()
    };
    eframe::run_native(
        "NCrypt",
        options,
        Box::new(|cc| {
            Ok(Box::new(NCryptApp::new(cc)))
        })
    )
}