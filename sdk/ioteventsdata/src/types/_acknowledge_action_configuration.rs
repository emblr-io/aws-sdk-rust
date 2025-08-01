// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the configuration information of an acknowledge action.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AcknowledgeActionConfiguration {
    /// <p>The note that you can leave when you acknowledge the alarm.</p>
    pub note: ::std::option::Option<::std::string::String>,
}
impl AcknowledgeActionConfiguration {
    /// <p>The note that you can leave when you acknowledge the alarm.</p>
    pub fn note(&self) -> ::std::option::Option<&str> {
        self.note.as_deref()
    }
}
impl AcknowledgeActionConfiguration {
    /// Creates a new builder-style object to manufacture [`AcknowledgeActionConfiguration`](crate::types::AcknowledgeActionConfiguration).
    pub fn builder() -> crate::types::builders::AcknowledgeActionConfigurationBuilder {
        crate::types::builders::AcknowledgeActionConfigurationBuilder::default()
    }
}

/// A builder for [`AcknowledgeActionConfiguration`](crate::types::AcknowledgeActionConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AcknowledgeActionConfigurationBuilder {
    pub(crate) note: ::std::option::Option<::std::string::String>,
}
impl AcknowledgeActionConfigurationBuilder {
    /// <p>The note that you can leave when you acknowledge the alarm.</p>
    pub fn note(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.note = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The note that you can leave when you acknowledge the alarm.</p>
    pub fn set_note(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.note = input;
        self
    }
    /// <p>The note that you can leave when you acknowledge the alarm.</p>
    pub fn get_note(&self) -> &::std::option::Option<::std::string::String> {
        &self.note
    }
    /// Consumes the builder and constructs a [`AcknowledgeActionConfiguration`](crate::types::AcknowledgeActionConfiguration).
    pub fn build(self) -> crate::types::AcknowledgeActionConfiguration {
        crate::types::AcknowledgeActionConfiguration { note: self.note }
    }
}
