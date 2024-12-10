use eframe::egui::{Color32, Stroke, Ui};
use super::{GUI, ui::{button, rich_text}};

pub fn show(ui: &mut Ui, gui: &mut GUI) {
    ui.set_max_width(120.0);

    ui.vertical_centered(|ui| {

    ui.scope(|ui| {

        ui.spacing_mut().item_spacing.y = 20.0;
        ui.visuals_mut().button_frame = true;

        // When hovered
        ui.visuals_mut().widgets.hovered.weak_bg_fill = Color32::from_rgba_premultiplied(55, 53, 53, 255);

        // At rest
        ui.visuals_mut().widgets.inactive.weak_bg_fill = Color32::TRANSPARENT;
        ui.visuals_mut().widgets.inactive.bg_stroke = Stroke::new(0.0, Color32::WHITE);


        if ui.add(button(rich_text("Encryption").size(16.0))).clicked() {
            gui.text_hashing_ui.open = false;
            gui.encryption_ui.open = true;
        }

        if ui.add(button(rich_text("Text Hashing").size(16.0))).clicked() {
            gui.text_hashing_ui.open = true;
            gui.encryption_ui.open = false;
        }

    });
});
}
