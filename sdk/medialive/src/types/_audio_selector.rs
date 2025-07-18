// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Audio Selector
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AudioSelector {
    /// The name of this AudioSelector. AudioDescriptions will use this name to uniquely identify this Selector. Selector names should be unique per input.
    pub name: ::std::option::Option<::std::string::String>,
    /// The audio selector settings.
    pub selector_settings: ::std::option::Option<crate::types::AudioSelectorSettings>,
}
impl AudioSelector {
    /// The name of this AudioSelector. AudioDescriptions will use this name to uniquely identify this Selector. Selector names should be unique per input.
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// The audio selector settings.
    pub fn selector_settings(&self) -> ::std::option::Option<&crate::types::AudioSelectorSettings> {
        self.selector_settings.as_ref()
    }
}
impl AudioSelector {
    /// Creates a new builder-style object to manufacture [`AudioSelector`](crate::types::AudioSelector).
    pub fn builder() -> crate::types::builders::AudioSelectorBuilder {
        crate::types::builders::AudioSelectorBuilder::default()
    }
}

/// A builder for [`AudioSelector`](crate::types::AudioSelector).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AudioSelectorBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) selector_settings: ::std::option::Option<crate::types::AudioSelectorSettings>,
}
impl AudioSelectorBuilder {
    /// The name of this AudioSelector. AudioDescriptions will use this name to uniquely identify this Selector. Selector names should be unique per input.
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// The name of this AudioSelector. AudioDescriptions will use this name to uniquely identify this Selector. Selector names should be unique per input.
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// The name of this AudioSelector. AudioDescriptions will use this name to uniquely identify this Selector. Selector names should be unique per input.
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// The audio selector settings.
    pub fn selector_settings(mut self, input: crate::types::AudioSelectorSettings) -> Self {
        self.selector_settings = ::std::option::Option::Some(input);
        self
    }
    /// The audio selector settings.
    pub fn set_selector_settings(mut self, input: ::std::option::Option<crate::types::AudioSelectorSettings>) -> Self {
        self.selector_settings = input;
        self
    }
    /// The audio selector settings.
    pub fn get_selector_settings(&self) -> &::std::option::Option<crate::types::AudioSelectorSettings> {
        &self.selector_settings
    }
    /// Consumes the builder and constructs a [`AudioSelector`](crate::types::AudioSelector).
    pub fn build(self) -> crate::types::AudioSelector {
        crate::types::AudioSelector {
            name: self.name,
            selector_settings: self.selector_settings,
        }
    }
}
