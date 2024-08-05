#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release

use eframe::{
    egui::{
        vec2, Align2, Vec2b, CentralPanel, Color32, Context, Frame, Margin, SidePanel, Slider, Style, TextEdit, Ui, Visuals, Window
    }, CreationContext
};
use num_format::{ Locale, ToFormattedString };
use std::sync::{ Arc, RwLock };
use encryption::prelude::*;
use lazy_static::lazy_static;

lazy_static! {
    pub static ref POP_MSG: Arc<RwLock<WindowMsg>> = Arc::new(RwLock::new(WindowMsg::default()));
}


/// The main application struct
pub struct NCryptApp {
    credentials: Credentials,
    file_path: String,
    argon_params: Argon2Params,
}

pub struct WindowMsg {
    pub open: bool,
    pub message: String,
}

impl Default for WindowMsg {
    fn default() -> Self {
        Self {
            open: false,
            message: Default::default(),
        }
    }
}

impl eframe::App for NCryptApp {
    // Main Execution Loop
    // This is where we draw the UI
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        // UI that belongs to the left panel
        SidePanel::left("left_panel")
            .exact_width(170.0)
            .show(ctx, |ui| {
                ui.add_space(20.0);
                self.argon_params_ui(ui);
            });

        // UI that belongs to the central panel
        CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                self.main_ui(ui);
            });

            // show a popup message if needed
            self.window_msg(ui);
        });
    }
}

impl NCryptApp {
    pub fn new(cc: &CreationContext) -> Self {
        let app = Self {
            credentials: Default::default(),
            file_path: Default::default(),
            argon_params: Default::default(),
        };

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

    pub fn main_ui(&mut self, ui: &mut Ui) {
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
                    self.file_path = path.to_str().unwrap().to_string();
                }
            }

            ui.add_space(15.0);
            ui.monospace(format!("File: {}", self.file_path));
        });
    }

    fn credentials_input(&mut self, ui: &mut Ui) {
        ui.vertical_centered(|ui| {
            ui.label("Enter your credentials:");
            ui.add_space(15.0);

            ui.label("Username:");
            ui.add(TextEdit::singleline(self.credentials.user_mut()).desired_width(200.0));

            ui.add_space(15.0);

            ui.label("Password:");
            ui.add(
                TextEdit::singleline(self.credentials.passwd_mut())
                    .password(true)
                    .desired_width(200.0)
            );

            ui.add_space(15.0);

            ui.label("Confrim Password:");
            ui.add(
                TextEdit::singleline(self.credentials.confirm_passwd_mut())
                    .password(true)
                    .desired_width(200.0)
            );
        });
    }

    fn encrypt(&mut self, ui: &mut Ui) {
        if ui.button("Encrypt").clicked() {
            {
                let mut pop_msg = POP_MSG.write().unwrap();
                pop_msg.open = true;
                pop_msg.message = "Encrypting...".to_string();
            }

            let argon_params = self.argon_params.clone();
            let file_path = self.file_path.clone();
            let credentials = self.credentials.clone();

            std::thread::spawn(move || {
                let data = match std::fs::read(file_path.clone()) {
                    Ok(data) => data,
                    Err(e) => {
                        let mut pop_msg = POP_MSG.write().unwrap();
                        pop_msg.open = true;
                        pop_msg.message = format!("Failed to read file: {:?}", e);
                        return;
                    }
                };

                let encrypted_data = match
                    encrypt_data(argon_params.clone(), data, credentials.clone())
                {
                    Ok(data) => data,
                    Err(e) => {
                        let mut pop_msg = POP_MSG.write().unwrap();
                        pop_msg.open = true;
                        pop_msg.message = format!("Failed to encrypt file: {:?}", e);
                        return;
                    }
                };

                let new_file_path = format!("{}.encrypted", file_path);

                match std::fs::write(&new_file_path, &encrypted_data) {
                    Ok(_) => {
                        let mut pop_msg = POP_MSG.write().unwrap();
                        pop_msg.open = true;
                        pop_msg.message = format!("File encrypted successfully to: {}", new_file_path);
                    }
                    Err(e) => {
                        let mut pop_msg = POP_MSG.write().unwrap();
                        pop_msg.open = true;
                        pop_msg.message = format!("Failed to save the encrypted file: {:?}", e);
                    }
                }
            });
        }
    }

    fn decrypt(&mut self, ui: &mut Ui) {
        if ui.button("Decrypt").clicked() {
            {
                let mut pop_msg = POP_MSG.write().unwrap();
                pop_msg.open = true;
                pop_msg.message = "Decrypting...".to_string();
            }

            let file_path = self.file_path.clone();
            let credentials = self.credentials.clone();

            std::thread::spawn(move || {
                let data = match std::fs::read(file_path.clone()) {
                    Ok(data) => data,
                    Err(e) => {
                        let mut pop_msg = POP_MSG.write().unwrap();
                        pop_msg.open = true;
                        pop_msg.message = format!("Failed to read file: {:?}", e);
                        return;
                    }
                };

                let decrypted_data = match decrypt_data(data, credentials.clone()) {
                    Ok(data) => data,
                    Err(e) => {
                        let mut pop_msg = POP_MSG.write().unwrap();
                        pop_msg.open = true;
                        pop_msg.message = format!("Failed to decrypt file: {:?}", e);
                        return;
                    }
                };

                // remove the .ecrypted extension
                let new_file_path = file_path.replace(".encrypted", "");

                match std::fs::write(&new_file_path, &decrypted_data) {
                    Ok(_) => {
                        let mut pop_msg = POP_MSG.write().unwrap();
                        pop_msg.open = true;
                        pop_msg.message = format!("File decrypted successfully to: {}", new_file_path);
                    }
                    Err(e) => {
                        let mut pop_msg = POP_MSG.write().unwrap();
                        pop_msg.open = true;
                        pop_msg.message = format!("Failed to save decrypted file: {:?}", e);
                    }
                }
            });
        }
    }

    fn argon_params_ui(&mut self, ui: &mut Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(15.0);
            ui.label("Argon2id Parameters:");
            ui.add_space(15.0);
            ui.label("Memory Cost (kB):");

            ui.add(
                Slider::new(&mut self.argon_params.m_cost, 2048..=256_000)
                    .drag_value_speed(100.0)
                    .custom_formatter(|v, _ctx| {
                        let v_as_int = v.round() as u32;
                        let formatted = v_as_int.to_formatted_string(&Locale::en);
                        format!("{}", formatted)
                    })
            );

            ui.add_space(15.0);
            ui.label("Iterations:");

            ui.add(
                Slider::new(&mut self.argon_params.t_cost, 100..=5000)
                    .drag_value_speed(100.0)
                    .custom_formatter(|v, _ctx| {
                        let v_as_int = v.round() as u32;
                        let formatted = v_as_int.to_formatted_string(&Locale::en);
                        format!("{}", formatted)
                    })
            );

            ui.add_space(15.0);
            ui.label("Parallelism:");
            ui.add(Slider::new(&mut self.argon_params.p_cost, 1..=64));

            ui.add_space(15.0);
        });
    }

    /// Show a popup window with a message
    pub fn window_msg(&mut self, ui: &mut Ui) {
        let msg;
        {
            let pop_msg = POP_MSG.read().unwrap();
            if !pop_msg.open {
                return;
            }
            msg = pop_msg.message.clone();
        }

        Window::new("Popup")
            .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
            .collapsible(false)
            .resizable(Vec2b::new(false, false))
            .title_bar(false)
            .show(ui.ctx(), |ui| {
                ui.set_min_size(vec2(300.0, 150.0));
                
                 ui.vertical_centered(|ui| {
           
                    ui.label(msg);
                    if ui.button("Ok").clicked() {
                        let mut pop_msg = POP_MSG.write().unwrap();
                        pop_msg.open = false;
                    }
                });
            });
    }
}
