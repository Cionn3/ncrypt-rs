use eframe::egui::{ Color32, Ui, Slider };
use num_format::{ Locale, ToFormattedString };
use std::sync::{ Arc, RwLock };
use encryption::prelude::*;
use super::*;

const FILE_EXTENSION: &str = ".ncrypt";

/// File Encryption/Decryption Ui
pub struct FileEncryptionUi {
    pub open: bool,

    pub credentials: Credentials,

    pub file_path: String,

    pub argon_params: Argon2Params,

    pub pop_msg: Arc<RwLock<WindowMsg>>,
}

impl FileEncryptionUi {
    pub fn new(pop_msg: Arc<RwLock<WindowMsg>>) -> Self {
        Self {
            open: true,
            credentials: Credentials::default(),
            file_path: String::new(),
            argon_params: Argon2Params::fast(),
            pop_msg,
        }
    }

    pub fn show(&mut self, ui: &mut Ui) {
        if !self.open {
            return;
        }

            self.open_file_button(ui);
            self.credentials_input(ui);

            ui.horizontal(|ui| {
                ui.add_space(160.0);
                self.encrypt(ui);

                ui.add_space(15.0);

                self.decrypt(ui);
            });
    }

    fn encrypt(&mut self, ui: &mut Ui) {
        let text = rich_text("Encrypt").color(Color32::BLACK);
        let button = button(text);

        if ui.add(button).clicked() {
            {
                let mut pop_msg = self.pop_msg.write().unwrap();
                pop_msg.open = true;
                pop_msg.message = "Encrypting...".to_string();
            }

            let argon_params = self.argon_params.clone();
            let file_path = self.file_path.clone();
            let credentials = self.credentials.clone();
            let pop_msg = self.pop_msg.clone();

            std::thread::spawn(move || {
                let data = match std::fs::read(file_path.clone()) {
                    Ok(data) => data,
                    Err(e) => {
                        let mut pop_msg = pop_msg.write().unwrap();
                        pop_msg.open = true;
                        pop_msg.title = "Failed to read file".to_string();
                        pop_msg.message = format!("{:?}", e);
                        return;
                    }
                };

                let encrypted_data = match encrypt_data(argon_params.clone(), data, credentials) {
                    Ok(data) => data,
                    Err(e) => {
                        let mut pop_msg = pop_msg.write().unwrap();
                        pop_msg.open = true;
                        pop_msg.title = "Failed to encrypt file".to_string();
                        pop_msg.message = format!("{:?}", e);
                        return;
                    }
                };

                let new_file_path = format!("{}{}", file_path, FILE_EXTENSION);

                match std::fs::write(&new_file_path, &encrypted_data) {
                    Ok(_) => {
                        let mut pop_msg = pop_msg.write().unwrap();
                        pop_msg.open = true;
                        pop_msg.title = "Success".to_string();
                        pop_msg.message =
                            format!("File encrypted successfully to: {}", new_file_path);
                    }
                    Err(e) => {
                        let mut pop_msg = pop_msg.write().unwrap();
                        pop_msg.open = true;
                        pop_msg.title = "Failed to save the encrypted file".to_string();
                        pop_msg.message = format!("{:?}", e);
                    }
                }
            });
        }
    }

    fn decrypt(&mut self, ui: &mut Ui) {
        let text = rich_text("Decrypt").color(Color32::BLACK);
        let button = button(text);

        if ui.add(button).clicked() {
            {
                let mut pop_msg = self.pop_msg.write().unwrap();
                pop_msg.open = true;
                pop_msg.message = "Decrypting...".to_string();
            }

            let file_path = self.file_path.clone();
            let credentials = self.credentials.clone();
            let pop_msg = self.pop_msg.clone();

            std::thread::spawn(move || {
                let data = match std::fs::read(file_path.clone()) {
                    Ok(data) => data,
                    Err(e) => {
                        let mut pop_msg = pop_msg.write().unwrap();
                        pop_msg.open = true;
                        pop_msg.title = "Failed to read file".to_string();
                        pop_msg.message = format!("{:?}", e);
                        return;
                    }
                };

                let decrypted_data = match decrypt_data(data, credentials) {
                    Ok(data) => data,
                    Err(e) => {
                        let mut pop_msg = pop_msg.write().unwrap();
                        pop_msg.open = true;
                        pop_msg.title = "Failed to decrypt file".to_string();
                        pop_msg.message = format!("{:?}", e);
                        return;
                    }
                };

                // remove the extension
                let new_file_path = file_path.replace(FILE_EXTENSION, "");

                match std::fs::write(&new_file_path, &decrypted_data) {
                    Ok(_) => {
                        let mut pop_msg = pop_msg.write().unwrap();
                        pop_msg.open = true;
                        pop_msg.title = "Success".to_string();
                        pop_msg.message =
                            format!("File decrypted successfully to: {}", new_file_path);
                    }
                    Err(e) => {
                        let mut pop_msg = pop_msg.write().unwrap();
                        pop_msg.open = true;
                        pop_msg.title = "Failed to save decrypted file".to_string();
                        pop_msg.message = format!("{:?}", e);
                    }
                }
            });
        }
    }

    fn open_file_button(&mut self, ui: &mut Ui) {
        let text = rich_text("Choose a File").color(Color32::BLACK);
        let button = button(text);

        ui.spacing_mut().item_spacing.y = 15.0;

        if ui.add(button).clicked() {
            if let Some(path) = rfd::FileDialog::new().pick_file() {
                self.file_path = path.to_str().unwrap().to_string();
            }
        }

        let file_text = rich_text(format!("File: {}", self.file_path));
        ui.label(file_text);

        ui.add_space(15.0);
    }

    fn credentials_input(&mut self, ui: &mut Ui) {
        ui.spacing_mut().item_spacing.y = 15.0;

        ui.label(rich_text("Enter Your Credentials"));

        ui.label(rich_text("Username:"));

        // username input
        ui.add(text_edit(self.credentials.user_mut()));

        ui.label(rich_text("Password:"));

        // password input
        ui.add(text_edit(self.credentials.passwd_mut()).password(true));

        ui.label(rich_text("Confrim Password:"));

        // confirm password input
        ui.add(text_edit(self.credentials.confirm_passwd_mut()).password(true));

        ui.add_space(15.0);
    }

    pub fn argon_params_ui(&mut self, ui: &mut Ui) {
        ui.vertical_centered(|ui| {
            ui.spacing_mut().item_spacing.y = 15.0;

            ui.label(rich_text("Memory Cost (kB)"));

            ui.add(
                Slider::new(&mut self.argon_params.m_cost, 2048..=10_000_000)
                    .drag_value_speed(100.0)
                    .custom_formatter(|v, _ctx| {
                        let v_as_int = v.round() as u32;
                        let formatted = v_as_int.to_formatted_string(&Locale::en);
                        format!("{}", formatted)
                    })
            );

            ui.label(rich_text("Iterations"));

            ui.add(
                Slider::new(&mut self.argon_params.t_cost, 1..=5000)
                    .drag_value_speed(100.0)
                    .custom_formatter(|v, _ctx| {
                        let v_as_int = v.round() as u32;
                        let formatted = v_as_int.to_formatted_string(&Locale::en);
                        format!("{}", formatted)
                    })
            );

            ui.label(rich_text("Parallelism"));

            ui.add(Slider::new(&mut self.argon_params.p_cost, 1..=64));
        });
    }
}
