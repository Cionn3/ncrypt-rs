#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release

use eframe::{ CreationContext, epaint::Shadow };
use egui::{ Color32, Context, Frame, Margin, Style, Ui, Visuals };
use argon2::{ Argon2, Params, Algorithm, Version };
use num_format::{Locale, ToFormattedString};

use n_crypt::*;

/// The main application struct that holds the UI logic
struct NCryptApp {
    ui: AppUI,
    app_data: AppData,
}

struct AppUI {
    pub show_window_msg: bool,
    pub message: String,
}

struct AppData {
    pub credentials: Credentials,
    pub file: File,
    pub argon_params: ArgonParams,
}

struct ArgonParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub hash_length: usize,
}

impl Default for ArgonParams {
    fn default() -> Self {
        Self {
            m_cost: 0,
            t_cost: 0,
            p_cost: 0,
            hash_length: 0,
        }
    }
}

impl Default for AppUI {
    fn default() -> Self {
        Self {
            show_window_msg: false,
            message: Default::default(),
        }
    }
}

impl Default for AppData {
    fn default() -> Self {
        Self {
            credentials: Default::default(),
            file: Default::default(),
            argon_params: Default::default(),
        }
    }
}

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1024.0, 500.0]),
        ..Default::default()
    };
    eframe::run_native(
        "nCrypt",
        options,
        Box::new(|cc| { Box::new(NCryptApp::new(cc)) })
    )
}

impl Default for NCryptApp {
    fn default() -> Self {
        Self {
            ui: Default::default(),
            app_data: Default::default(),
        }
    }
}

impl eframe::App for NCryptApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::SidePanel
            ::left("left_panel")
            .exact_width(170.0)
            .show(ctx, |ui| {
                ui.add_space(10.0);
                self.argon_params_ui(ui);
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                self.build_ui(ui);
            });
            // show window message if needed
            if self.ui.show_window_msg {
                self.window_msg(ui);
            }
        });
    }
}

impl NCryptApp {
    fn new(cc: &CreationContext) -> Self {
        let app = Self::default();
        app.set_background_color(&cc.egui_ctx);
        app
    }

    fn set_background_color(&self, ctx: &Context) {
        let visuals = Visuals {
            panel_fill: Color32::from_hex("#212529").unwrap(),
            ..Visuals::default()
        };
        let style = Style {
            visuals,
            ..Style::default()
        };
        ctx.set_style(style);
    }

    pub fn build_ui(&mut self, ui: &mut Ui) {
        let panel_frame = Frame {
            inner_margin: Margin::same(8.0),
            outer_margin: Margin::same(8.0),
            fill: Color32::from_hex("#212529").unwrap(),
            ..Frame::default()
        };

        panel_frame.show(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.set_width(500.0);
                ui.set_height(400.0);

                self.open_file_button(ui);

                ui.add_space(15.0);

                self.credentials_input(ui);

                ui.add_space(15.0);

                ui.horizontal(|ui| {
                    ui.add_space(185.0);
                    self.encrypt(ui);
                    ui.add_space(15.0);
                    self.decrypt(ui);
                });
            });
        });
    }

    fn open_file_button(&mut self, ui: &mut Ui) {
        ui.vertical_centered(|ui| {
            if ui.button("Choose a file…").clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_file() {
                    self.app_data.file.path = path.display().to_string();
                }
            }
            ui.add_space(15.0);
            ui.monospace(&self.app_data.file.path);
        });
    }

    fn credentials_input(&mut self, ui: &mut Ui) {
        ui.vertical_centered(|ui| {
            ui.label("Enter your credentials:");
            ui.add_space(15.0);

            ui.label("Username:");
            ui.add(
                egui::TextEdit
                    ::singleline(&mut self.app_data.credentials.username)
                    .desired_width(200.0)
            );

            ui.add_space(15.0);

            ui.label("Password:");
            ui.add(
                egui::TextEdit
                    ::singleline(&mut self.app_data.credentials.password)
                    .password(true)
                    .desired_width(200.0)
            );

            ui.add_space(15.0);

            ui.label("Confrim Password:");
            ui.add(
                egui::TextEdit
                    ::singleline(&mut self.app_data.credentials.confrim_password)
                    .password(true)
                    .desired_width(200.0)
            );
        });
    }

    fn encrypt(&mut self, ui: &mut Ui) {
        
            if ui.button("Encrypt").clicked() {
                let file = File::new(self.app_data.file.path.clone());
                let credentials = self.app_data.credentials.clone();
                println!("File Path: {}", file.path);
                println!("File Extension: {}", file.extension);

                let params = match
                    Params::new(
                        self.app_data.argon_params.t_cost,
                        self.app_data.argon_params.m_cost,
                        self.app_data.argon_params.p_cost,
                        Some(self.app_data.argon_params.hash_length)
                    )
                {
                    Ok(params) => params,
                    Err(e) => {
                        println!("Error: {:?}", e);
                        self.ui.message = format!("Error: {:?}", e);
                        self.ui.show_window_msg = true;
                        return;
                    }
                };

                let argon2 = Argon2::new(Algorithm::default(), Version::default(), params.clone());

                match encrypt(argon2, credentials, file) {
                    Ok(_) => {
                        self.ui.message = format!("{}\nLocation: {}", SUCCESS_ENCRYPT, self.app_data.file.name_encrypted());
                        self.ui.show_window_msg = true;
                    }
                    Err(e) => {
                        println!("Error: {:?}", e);
                        self.ui.message = format!("Error: {:?}", e);
                        self.ui.show_window_msg = true;
                    }
                }
            }
        
    }

    fn decrypt(&mut self, ui: &mut Ui) {
        
            if ui.button("Decrypt").clicked() {
                let file = File::new(self.app_data.file.path.clone());
                let credentials = self.app_data.credentials.clone();


                match decrypt(file, credentials) {
                    Ok(_) => {
                        self.ui.message = format!("{}\nLocation: {}", SUCCESS_DECRYPT, self.app_data.file.name_decrypted());
                        self.ui.show_window_msg = true;
                    }
                    Err(e) => {
                        println!("Error: {:?}", e);
                        self.ui.message = format!("Error: {:?}", e);
                        self.ui.show_window_msg = true;
                    }
                }
            }
        
    }

    fn argon_params_ui(&mut self, ui: &mut Ui) {
        ui.vertical_centered(|ui| {
            ui.label("Argon2id Parameters:");
            ui.add_space(15.0);
            ui.label("Memory Cost (kB):");

            ui.add(egui::Slider::new(&mut self.app_data.argon_params.m_cost, 1024..=MAX_M_COST)
            .drag_value_speed(100.0)
            .custom_formatter(|v, _ctx| {
                
                let v_as_int = v.round() as u32;
                let formatted = v_as_int.to_formatted_string(&Locale::en);
                format!("{}", formatted)
            }));

            ui.add_space(15.0);
            ui.label("Iterations:");

            ui.add(egui::Slider::new(&mut self.app_data.argon_params.t_cost, 1000..=MAX_T_COST)
            .drag_value_speed(100.0)
            .custom_formatter(|v, _ctx| {
                
                let v_as_int = v.round() as u32;
                let formatted = v_as_int.to_formatted_string(&Locale::en);
                format!("{}", formatted)
            }));

            ui.add_space(15.0);
            ui.label("Parallelism:");
            ui.add(egui::Slider::new(&mut self.app_data.argon_params.p_cost, 1..=MAX_P_COST));
            ui.add_space(15.0);
            ui.label("Hash Length:");
            ui.add(egui::Slider::new(&mut self.app_data.argon_params.hash_length, 32..=MAX_HASH_LENGTH));

            ui.add_space(15.0);
        });
    }

    /// Show a popup window with a message
    pub fn window_msg(&mut self, ui: &mut Ui) {
        egui::Area
            ::new("Popup")
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ui.ctx(), |ui| {
                let panel_frame = Frame {
                    inner_margin: Margin::same(75.0),
                    fill: Color32::from_hex("#212529").unwrap(),
                    shadow: Shadow {
                        extrusion: 1.0,
                        color: Color32::WHITE,
                    },
                    ..Frame::default()
                };
                panel_frame.show(ui, |ui| {
                    ui.label(self.ui.message.clone());
                    if ui.button("Ok").clicked() {
                        self.ui.show_window_msg = false;
                    }
                });
            });
    }
}