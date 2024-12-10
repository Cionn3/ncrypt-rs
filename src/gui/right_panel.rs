use eframe::egui::Ui;
use super::GUI;

pub fn show(ui: &mut Ui, gui: &mut GUI) {
    gui.encryption_ui.argon_params_ui(ui);
}
