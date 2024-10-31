pub mod central_panel;
pub mod left_panel;

use eframe::egui::{Button, Color32, TextEdit, RichText, Sense, WidgetText};

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



pub fn rich_text(text: impl Into<String>) -> RichText {
    RichText::new(text)
        .size(13.0)
        .color(Color32::WHITE)
}

pub fn button(text: impl Into<WidgetText>) -> Button<'static> {
    Button::new(text)
        .sense(Sense::click())
}

pub fn text_edit(text: &mut String) -> TextEdit<'_> {
    TextEdit::singleline(text)
        .desired_width(200.0)
        .text_color(Color32::WHITE)
}