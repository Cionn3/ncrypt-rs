use eframe::egui::{Slider, Ui };
use crate::app::NCryptApp;
use num_format::{ Locale, ToFormattedString };
use super::*;

pub fn show(ui: &mut Ui, app: &mut NCryptApp) {
    argon_params_ui(ui, app);
}

fn argon_params_ui(ui: &mut Ui, app: &mut NCryptApp) {
    ui.vertical_centered(|ui| {
        ui.spacing_mut().item_spacing.y = 15.0;

        let memory_text = rich_text("Memory Cost (kB)");
        ui.label(memory_text);

        ui.add(
            Slider::new(&mut app.argon_params.m_cost, 2048..=10_000_000)
                .drag_value_speed(100.0)
                .custom_formatter(|v, _ctx| {
                    let v_as_int = v.round() as u32;
                    let formatted = v_as_int.to_formatted_string(&Locale::en);
                    format!("{}", formatted)
                })
        );

        let iterations_text = rich_text("Iterations");
        ui.label(iterations_text);

        ui.add(
            Slider::new(&mut app.argon_params.t_cost, 1..=5000)
                .drag_value_speed(100.0)
                .custom_formatter(|v, _ctx| {
                    let v_as_int = v.round() as u32;
                    let formatted = v_as_int.to_formatted_string(&Locale::en);
                    format!("{}", formatted)
                })
        );

        let parallelism_text = rich_text("Parallelism");
        ui.label(parallelism_text);

        ui.add(Slider::new(&mut app.argon_params.p_cost, 1..=64));
    });
}
