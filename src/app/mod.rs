use eframe::{
    egui::{
        CentralPanel,
        Color32,
        Context,
        Frame,
        Margin,
        Rgba,
        Rounding,
        SidePanel,
        Stroke,
        Ui,
        Visuals,
        Style,
    },
    CreationContext,
};
use encryption::zeroize::Zeroize;

use std::time::Duration;
use crate::gui::{ central_panel, left_panel, right_panel, GUI };
use window::window_frame;

pub mod window;

/// The main application struct
pub struct NCryptApp {
    pub gui: GUI,
}

impl NCryptApp {
    pub fn new(cc: &CreationContext) -> Self {
        let ctx = cc.egui_ctx.clone();
        std::thread::spawn(move || request_repaint(ctx));

        let app = Self {
            gui: GUI::new(),
        };

        Self::set_style(&cc.egui_ctx);

        app
    }

    fn set_style(ctx: &Context) {
        let visuals = Visuals::dark();
        let mut style = Style::default();

        style.visuals = visuals;

        // Bg color of widgets like TextEdit
        style.visuals.extreme_bg_color = Color32::TRANSPARENT;

        // Hide the separator lines
        style.visuals.widgets.noninteractive.bg_stroke = Stroke::NONE;

        // Widgets rounding
        style.visuals.widgets.inactive.rounding = Rounding::same(5.0);

        // Widgets Stroke
        style.visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, Color32::WHITE);

        ctx.set_style(style)
    }
}

impl eframe::App for NCryptApp {
    fn clear_color(&self, _visuals: &Visuals) -> [f32; 4] {
        Rgba::TRANSPARENT.to_array() // Make sure we don't paint anything behind the rounded corners
    }

    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        window_frame(ctx, "nCrypt 1.0.0", |ui| {
            apply_visuals(ui);

            let frame = Frame::none().fill(Color32::from_hex("#212529").unwrap());

            // UI that belongs to the right panel
            SidePanel::right("right_panel")
                .min_width(50.0)
                .resizable(false)
                .frame(
                    frame.clone().inner_margin(Margin { left: 20.0, right: 0.0, top: 100.0, bottom: 0.0 })
                )
                .show_inside(ui, |ui| {
                    right_panel::show(ui, &mut self.gui);
                });
    

            // UI that belongs to the left panel
            SidePanel::left("left_panel")
                .min_width(50.0)
                .resizable(false)
                .frame(
                    frame.clone().inner_margin(Margin { left: 0.0, right: 0.0, top: 100.0, bottom: 0.0 })
                )
                .show_inside(ui, |ui| {
                    left_panel::show(ui, &mut self.gui);
                });

            // UI that belongs to the central panel
            CentralPanel::default()
                .frame(
                    frame.inner_margin(Margin { left: 0.0, right: 0.0, top: 30.0, bottom: 0.0 })
                )
                .show_inside(ui, |ui| {
                    central_panel::show(ui, &mut self.gui);
                });
        });
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.gui.encryption_ui.credentials.destroy();
        self.gui.text_hashing_ui.input_text.zeroize();
        self.gui.text_hashing_ui.output_hash.zeroize();
    }
}

/// Request repaint every 32ms (30 FPS) only if the Viewport is not minimized.
fn request_repaint(ctx: Context) {
    let duration = Duration::from_millis(32);

    loop {
        let is_minimized = ctx.input(|i| i.viewport().minimized.unwrap_or(false));

        if !is_minimized {
            ctx.request_repaint();
        }
        std::thread::sleep(duration);
    }
}

pub fn apply_visuals(ui: &mut Ui) {
    ui.visuals_mut().dark_mode = true;

    // Bg color of widgets like TextEdit
    ui.visuals_mut().extreme_bg_color = Color32::TRANSPARENT;

    // Hide the separator lines
    ui.visuals_mut().widgets.noninteractive.bg_stroke = Stroke::NONE;

    // Widgets rounding
    ui.visuals_mut().widgets.inactive.rounding = Rounding::same(5.0);

    // Widgets Stroke
    ui.visuals_mut().widgets.inactive.bg_stroke = Stroke::new(1.0, Color32::WHITE);
}
