use eframe::egui::{ vec2, Align2, Color32, Frame, Ui, Vec2b, Window };
use std::sync::{ Arc, RwLock };
use encryption::prelude::*;
use crate::app::NCryptApp;
use super::*;

const FILE_EXTENSION: &str = ".ncrypt";


pub fn show(ui: &mut Ui, app: &mut NCryptApp) {
    ui.vertical_centered(|ui| {
        ui.set_max_width(250.0);
        ui.set_max_height(300.0);

        open_file_button(ui, app);
        credentials_input(ui, app);

        
        ui.horizontal_centered(|ui| {
            ui.add_space(60.0);
            encrypt(ui, app);

            ui.add_space(15.0);

            decrypt(ui, app);
        });
         
    });

    window_msg(ui, app.pop_msg.clone());
}

fn open_file_button(ui: &mut Ui, app: &mut NCryptApp) {
   
        let text = rich_text("Choose a File").color(Color32::BLACK);
        let button = button(text);

        ui.spacing_mut().item_spacing.y = 15.0;

        if ui.add(button).clicked() {
            if let Some(path) = rfd::FileDialog::new().pick_file() {
                app.file_path = path.to_str().unwrap().to_string();
            }
        }

        let file_text = rich_text(format!("File: {}", app.file_path));
        ui.label(file_text);

        ui.add_space(15.0);
  
}

fn credentials_input(ui: &mut Ui, app: &mut NCryptApp) {
    
        ui.spacing_mut().item_spacing.y = 15.0;

        let credentials_text = rich_text("Enter Your Credentials");
        ui.label(credentials_text);

        let username_text = rich_text("Username:");
        ui.label(username_text);

        // username input
        ui.add(text_edit(app.credentials.user_mut()));

        let password_text = rich_text("Password:");
        ui.label(password_text);

        // password input
        ui.add(text_edit(app.credentials.passwd_mut()).password(true));

        let confirm_password_text = rich_text("Confrim Password:");
        ui.label(confirm_password_text);

        // confirm password input
        ui.add(text_edit(app.credentials.confirm_passwd_mut()).password(true));

        ui.add_space(15.0);
    
}

fn encrypt(ui: &mut Ui, app: &mut NCryptApp) {
    let text = rich_text("Encrypt").color(Color32::BLACK);
    let button = button(text);

    if ui.add(button).clicked() {
        {
            let mut pop_msg = app.pop_msg.write().unwrap();
            pop_msg.open = true;
            pop_msg.message = "Encrypting...".to_string();
        }

        let argon_params = app.argon_params.clone();
        let file_path = app.file_path.clone();
        let credentials = app.credentials.clone();
        let pop_msg = app.pop_msg.clone();

        std::thread::spawn(move || {
            let data = match std::fs::read(file_path.clone()) {
                Ok(data) => data,
                Err(e) => {
                    let mut pop_msg = pop_msg.write().unwrap();
                    pop_msg.open = true;
                    pop_msg.message = format!("Failed to read file: {:?}", e);
                    return;
                }
            };

            let encrypted_data = match encrypt_data(argon_params.clone(), data, credentials) {
                Ok(data) => data,
                Err(e) => {
                    let mut pop_msg = pop_msg.write().unwrap();
                    pop_msg.open = true;
                    pop_msg.message = format!("Failed to encrypt file: {:?}", e);
                    return;
                }
            };

            let new_file_path = format!("{}{}", file_path, FILE_EXTENSION);

            match std::fs::write(&new_file_path, &encrypted_data) {
                Ok(_) => {
                    let mut pop_msg = pop_msg.write().unwrap();
                    pop_msg.open = true;
                    pop_msg.message = format!("File encrypted successfully to: {}", new_file_path);
                }
                Err(e) => {
                    let mut pop_msg = pop_msg.write().unwrap();
                    pop_msg.open = true;
                    pop_msg.message = format!("Failed to save the encrypted file: {:?}", e);
                }
            }
        });
    }
}

fn decrypt(ui: &mut Ui, app: &mut NCryptApp) {
    let text = rich_text("Decrypt").color(Color32::BLACK);
    let button = button(text);

    if ui.add(button).clicked() {
        {
            let mut pop_msg = app.pop_msg.write().unwrap();
            pop_msg.open = true;
            pop_msg.message = "Decrypting...".to_string();
        }

        let file_path = app.file_path.clone();
        let credentials = app.credentials.clone();
        let pop_msg = app.pop_msg.clone();

        std::thread::spawn(move || {
            let data = match std::fs::read(file_path.clone()) {
                Ok(data) => data,
                Err(e) => {
                    let mut pop_msg = pop_msg.write().unwrap();
                    pop_msg.open = true;
                    pop_msg.message = format!("Failed to read file: {:?}", e);
                    return;
                }
            };

            let decrypted_data = match decrypt_data(data, credentials) {
                Ok(data) => data,
                Err(e) => {
                    let mut pop_msg = pop_msg.write().unwrap();
                    pop_msg.open = true;
                    pop_msg.message = format!("Failed to decrypt file: {:?}", e);
                    return;
                }
            };

            // remove the .ecrypted extension
            let new_file_path = file_path.replace(FILE_EXTENSION, "");

            match std::fs::write(&new_file_path, &decrypted_data) {
                Ok(_) => {
                    let mut pop_msg = pop_msg.write().unwrap();
                    pop_msg.open = true;
                    pop_msg.message = format!("File decrypted successfully to: {}", new_file_path);
                }
                Err(e) => {
                    let mut pop_msg = pop_msg.write().unwrap();
                    pop_msg.open = true;
                    pop_msg.message = format!("Failed to save decrypted file: {:?}", e);
                }
            }
        });
    }
}

/// Show a popup window with a message
pub fn window_msg(ui: &mut Ui, pop_msg: Arc<RwLock<WindowMsg>>) {
    let msg;
    {
        let pop_msg = pop_msg.read().unwrap();
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
        .frame(Frame::window(&ui.style().clone()).fill(Color32::from_hex("#212529").unwrap()))
        .show(ui.ctx(), |ui| {
            ui.set_min_size(vec2(300.0, 150.0));

            ui.vertical_centered(|ui| {
                ui.spacing_mut().item_spacing.y = 15.0;

                let msg_text = rich_text(msg);
                ui.label(msg_text);

                let button = button("Ok");
                
                if ui.add(button).clicked() {
                    let mut pop_msg = pop_msg.write().unwrap();
                    pop_msg.open = false;
                }
            });
        });
}
