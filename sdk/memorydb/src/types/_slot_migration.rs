// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the progress of an online resharding operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SlotMigration {
    /// <p>The percentage of the slot migration that is complete.</p>
    pub progress_percentage: f64,
}
impl SlotMigration {
    /// <p>The percentage of the slot migration that is complete.</p>
    pub fn progress_percentage(&self) -> f64 {
        self.progress_percentage
    }
}
impl SlotMigration {
    /// Creates a new builder-style object to manufacture [`SlotMigration`](crate::types::SlotMigration).
    pub fn builder() -> crate::types::builders::SlotMigrationBuilder {
        crate::types::builders::SlotMigrationBuilder::default()
    }
}

/// A builder for [`SlotMigration`](crate::types::SlotMigration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SlotMigrationBuilder {
    pub(crate) progress_percentage: ::std::option::Option<f64>,
}
impl SlotMigrationBuilder {
    /// <p>The percentage of the slot migration that is complete.</p>
    pub fn progress_percentage(mut self, input: f64) -> Self {
        self.progress_percentage = ::std::option::Option::Some(input);
        self
    }
    /// <p>The percentage of the slot migration that is complete.</p>
    pub fn set_progress_percentage(mut self, input: ::std::option::Option<f64>) -> Self {
        self.progress_percentage = input;
        self
    }
    /// <p>The percentage of the slot migration that is complete.</p>
    pub fn get_progress_percentage(&self) -> &::std::option::Option<f64> {
        &self.progress_percentage
    }
    /// Consumes the builder and constructs a [`SlotMigration`](crate::types::SlotMigration).
    pub fn build(self) -> crate::types::SlotMigration {
        crate::types::SlotMigration {
            progress_percentage: self.progress_percentage.unwrap_or_default(),
        }
    }
}
