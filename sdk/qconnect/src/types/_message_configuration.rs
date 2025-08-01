// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The configuration for a <a href="https://docs.aws.amazon.com/connect/latest/APIReference/API_amazon-q-connect_SendMessage.html">SendMessage</a> request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MessageConfiguration {
    /// <p>Generates a filler response when tool selection is <code>QUESTION</code>.</p>
    pub generate_filler_message: ::std::option::Option<bool>,
}
impl MessageConfiguration {
    /// <p>Generates a filler response when tool selection is <code>QUESTION</code>.</p>
    pub fn generate_filler_message(&self) -> ::std::option::Option<bool> {
        self.generate_filler_message
    }
}
impl MessageConfiguration {
    /// Creates a new builder-style object to manufacture [`MessageConfiguration`](crate::types::MessageConfiguration).
    pub fn builder() -> crate::types::builders::MessageConfigurationBuilder {
        crate::types::builders::MessageConfigurationBuilder::default()
    }
}

/// A builder for [`MessageConfiguration`](crate::types::MessageConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MessageConfigurationBuilder {
    pub(crate) generate_filler_message: ::std::option::Option<bool>,
}
impl MessageConfigurationBuilder {
    /// <p>Generates a filler response when tool selection is <code>QUESTION</code>.</p>
    pub fn generate_filler_message(mut self, input: bool) -> Self {
        self.generate_filler_message = ::std::option::Option::Some(input);
        self
    }
    /// <p>Generates a filler response when tool selection is <code>QUESTION</code>.</p>
    pub fn set_generate_filler_message(mut self, input: ::std::option::Option<bool>) -> Self {
        self.generate_filler_message = input;
        self
    }
    /// <p>Generates a filler response when tool selection is <code>QUESTION</code>.</p>
    pub fn get_generate_filler_message(&self) -> &::std::option::Option<bool> {
        &self.generate_filler_message
    }
    /// Consumes the builder and constructs a [`MessageConfiguration`](crate::types::MessageConfiguration).
    pub fn build(self) -> crate::types::MessageConfiguration {
        crate::types::MessageConfiguration {
            generate_filler_message: self.generate_filler_message,
        }
    }
}
