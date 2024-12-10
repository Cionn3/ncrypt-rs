pub mod ui;
pub mod central_panel;
pub mod left_panel;
pub mod right_panel;

use eframe::egui::Ui;
use std::sync::{Arc, RwLock};
use ui::{WindowMsg, file_encryption::FileEncryptionUi, text_hashing::TextHashingUi};


pub struct GUI {

    pub encryption_ui: FileEncryptionUi,

    pub text_hashing_ui: TextHashingUi,

    pub pop_msg: Arc<RwLock<WindowMsg>>
}

impl GUI {
    pub fn new() -> Self {
        let pop_msg = Arc::new(RwLock::new(WindowMsg::default()));
        Self {
            encryption_ui: FileEncryptionUi::new(pop_msg.clone()),
            text_hashing_ui: TextHashingUi::new(),
            pop_msg
        }
    }

    pub fn show_central_panel(&mut self, ui: &mut Ui) {
        central_panel::show(ui, self);
    }

    pub fn show_left_panel(&mut self, ui: &mut Ui) {
         left_panel::show(ui, self);
    }
}