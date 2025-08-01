// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about the observed behavior.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Observations {
    /// <p>The text that was unusual.</p>
    pub text: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl Observations {
    /// <p>The text that was unusual.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.text.is_none()`.
    pub fn text(&self) -> &[::std::string::String] {
        self.text.as_deref().unwrap_or_default()
    }
}
impl Observations {
    /// Creates a new builder-style object to manufacture [`Observations`](crate::types::Observations).
    pub fn builder() -> crate::types::builders::ObservationsBuilder {
        crate::types::builders::ObservationsBuilder::default()
    }
}

/// A builder for [`Observations`](crate::types::Observations).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ObservationsBuilder {
    pub(crate) text: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ObservationsBuilder {
    /// Appends an item to `text`.
    ///
    /// To override the contents of this collection use [`set_text`](Self::set_text).
    ///
    /// <p>The text that was unusual.</p>
    pub fn text(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.text.unwrap_or_default();
        v.push(input.into());
        self.text = ::std::option::Option::Some(v);
        self
    }
    /// <p>The text that was unusual.</p>
    pub fn set_text(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.text = input;
        self
    }
    /// <p>The text that was unusual.</p>
    pub fn get_text(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.text
    }
    /// Consumes the builder and constructs a [`Observations`](crate::types::Observations).
    pub fn build(self) -> crate::types::Observations {
        crate::types::Observations { text: self.text }
    }
}
