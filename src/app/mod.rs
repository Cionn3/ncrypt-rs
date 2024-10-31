use eframe::{
    egui::{CentralPanel, Color32, Context, Frame, Margin, Rgba, Rounding, SidePanel, Stroke, Ui, Visuals },
    CreationContext,
};

use std::time::Duration;
use encryption::prelude::*;
use std::sync::{ Arc, RwLock };
use crate::gui::ui::{ WindowMsg, left_panel, central_panel };
use window::window_frame;

pub mod window;

/// The main application struct
pub struct NCryptApp {
    pub credentials: Credentials,
    pub file_path: String,
    pub argon_params: Argon2Params,
    pub pop_msg: Arc<RwLock<WindowMsg>>,
}

impl NCryptApp {
    pub fn new(cc: &CreationContext) -> Self {
        let ctx = cc.egui_ctx.clone();
        std::thread::spawn(move || request_repaint(ctx));

        let app = Self {
            credentials: Default::default(),
            file_path: Default::default(),
            argon_params: Argon2Params::fast(),
            pop_msg: Arc::new(RwLock::new(WindowMsg::default())),
        };

        app
    }

}

impl eframe::App for NCryptApp {

    fn clear_color(&self, _visuals: &Visuals) -> [f32; 4] {
        Rgba::TRANSPARENT.to_array() // Make sure we don't paint anything behind the rounded corners
    }


    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
       

        window_frame(ctx, "nCrypt", |ui| {

        apply_visuals(ui);

        let frame = Frame::none().fill(Color32::from_hex("#212529").unwrap());


        // UI that belongs to the left panel
        SidePanel::left("left_panel")
            .min_width(100.0)
            .resizable(false)
            .frame(frame.clone())
            .show_inside(ui, |ui| {
                left_panel::show(ui, self);
            });

        // UI that belongs to the central panel
        CentralPanel::default()
            .frame(frame.inner_margin(Margin {left: 0.0, right: 200.0, top: 30.0, bottom: 0.0}))
            .show_inside(ui, |ui| {
                central_panel::show(ui, self);
            });
            

        });

    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.credentials.destroy();
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