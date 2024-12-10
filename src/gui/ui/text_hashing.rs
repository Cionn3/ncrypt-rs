use eframe::egui::{ Ui, ComboBox, TextEdit, Color32, FontSelection, FontId };
use super::rich_text;
use sha3::{ Digest, Sha3_224, Sha3_256, Sha3_384, Sha3_512 };

#[derive(Clone, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
}

impl HashAlgorithm {
    pub fn to_string(&self) -> String {
        (
            match self {
                HashAlgorithm::Sha3_224 => "SHA3-224",
                HashAlgorithm::Sha3_256 => "SHA3-256",
                HashAlgorithm::Sha3_384 => "SHA3-384",
                HashAlgorithm::Sha3_512 => "SHA3-512",
            }
        ).to_string()
    }

    pub fn to_vec(&self) -> Vec<HashAlgorithm> {
        vec![
            HashAlgorithm::Sha3_224,
            HashAlgorithm::Sha3_256,
            HashAlgorithm::Sha3_384,
            HashAlgorithm::Sha3_512
        ]
    }
}

pub struct TextHashingUi {
    pub open: bool,
    pub algorithm: HashAlgorithm,
    pub input_text: String,
    pub output_hash: String,
}

impl TextHashingUi {
    pub fn new() -> Self {
        Self {
            open: false,
            algorithm: HashAlgorithm::Sha3_224,
            input_text: String::new(),
            output_hash: String::new(),
        }
    }

    pub fn show(&mut self, ui: &mut Ui) {
        if !self.open {
            return;
        }

        let font = FontSelection::FontId(FontId::monospace(13.0));
        let font_2 = FontSelection::FontId(FontId::monospace(13.0));

        ui.spacing_mut().item_spacing.y = 10.0;

        self.select_algorithm(ui);

        ui.label(rich_text("Input Text").size(16.0));

        let input_edit = TextEdit::multiline(&mut self.input_text)
            .desired_width(300.0)
            .desired_rows(10)
            .text_color(Color32::WHITE)
            .font(font);
        ui.add(input_edit);

        ui.label(rich_text("Hash Output").size(16.0));

        let output_edit = TextEdit::multiline(&mut self.output_hash)
            .desired_width(300.0)
            .desired_rows(10)
            .text_color(Color32::WHITE)
            .font(font_2);
        ui.add(output_edit);

        if !self.input_text.is_empty() {
            self.calculate_hash();
        } else {
            self.output_hash.clear();
        }
    }

    pub fn calculate_hash(&mut self) {
        if self.algorithm == HashAlgorithm::Sha3_224 {
            let mut hasher = Sha3_224::new();
            hasher.update(self.input_text.as_bytes());
            let result = hasher.finalize();
            self.output_hash = format!("{:x}", result);
        } else if self.algorithm == HashAlgorithm::Sha3_256 {
            let mut hasher = Sha3_256::new();
            hasher.update(self.input_text.as_bytes());
            let result = hasher.finalize();
            self.output_hash = format!("{:x}", result);
        } else if self.algorithm == HashAlgorithm::Sha3_384 {
            let mut hasher = Sha3_384::new();
            hasher.update(self.input_text.as_bytes());
            let result = hasher.finalize();
            self.output_hash = format!("{:x}", result);
        } else {
            let mut hasher = Sha3_512::new();
            hasher.update(self.input_text.as_bytes());
            let result = hasher.finalize();
            self.output_hash = format!("{:x}", result);
        }
    }

    fn select_algorithm(&mut self, ui: &mut Ui) {
        ComboBox::from_label("")
            .selected_text(self.algorithm.to_string())
            .show_ui(ui, |ui| {
                let mut algorithms = self.algorithm.to_vec();

                for selected_algorithm in algorithms.iter_mut() {
                    let value = ui.selectable_value(
                        &mut self.algorithm,
                        selected_algorithm.clone(),
                        selected_algorithm.to_string()
                    );

                    if value.clicked() {
                        self.algorithm = selected_algorithm.clone();
                    }
                }
            });
    }
}