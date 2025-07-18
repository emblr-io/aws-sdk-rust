// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The logo configuration.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LogoConfiguration {
    /// <p>The alt text for the logo.</p>
    pub alt_text: ::std::string::String,
    /// <p>A set of configured logos.</p>
    pub logo_set: ::std::option::Option<crate::types::LogoSetConfiguration>,
}
impl LogoConfiguration {
    /// <p>The alt text for the logo.</p>
    pub fn alt_text(&self) -> &str {
        use std::ops::Deref;
        self.alt_text.deref()
    }
    /// <p>A set of configured logos.</p>
    pub fn logo_set(&self) -> ::std::option::Option<&crate::types::LogoSetConfiguration> {
        self.logo_set.as_ref()
    }
}
impl LogoConfiguration {
    /// Creates a new builder-style object to manufacture [`LogoConfiguration`](crate::types::LogoConfiguration).
    pub fn builder() -> crate::types::builders::LogoConfigurationBuilder {
        crate::types::builders::LogoConfigurationBuilder::default()
    }
}

/// A builder for [`LogoConfiguration`](crate::types::LogoConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LogoConfigurationBuilder {
    pub(crate) alt_text: ::std::option::Option<::std::string::String>,
    pub(crate) logo_set: ::std::option::Option<crate::types::LogoSetConfiguration>,
}
impl LogoConfigurationBuilder {
    /// <p>The alt text for the logo.</p>
    /// This field is required.
    pub fn alt_text(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.alt_text = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The alt text for the logo.</p>
    pub fn set_alt_text(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.alt_text = input;
        self
    }
    /// <p>The alt text for the logo.</p>
    pub fn get_alt_text(&self) -> &::std::option::Option<::std::string::String> {
        &self.alt_text
    }
    /// <p>A set of configured logos.</p>
    /// This field is required.
    pub fn logo_set(mut self, input: crate::types::LogoSetConfiguration) -> Self {
        self.logo_set = ::std::option::Option::Some(input);
        self
    }
    /// <p>A set of configured logos.</p>
    pub fn set_logo_set(mut self, input: ::std::option::Option<crate::types::LogoSetConfiguration>) -> Self {
        self.logo_set = input;
        self
    }
    /// <p>A set of configured logos.</p>
    pub fn get_logo_set(&self) -> &::std::option::Option<crate::types::LogoSetConfiguration> {
        &self.logo_set
    }
    /// Consumes the builder and constructs a [`LogoConfiguration`](crate::types::LogoConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`alt_text`](crate::types::builders::LogoConfigurationBuilder::alt_text)
    pub fn build(self) -> ::std::result::Result<crate::types::LogoConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::LogoConfiguration {
            alt_text: self.alt_text.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "alt_text",
                    "alt_text was not specified but it is required when building LogoConfiguration",
                )
            })?,
            logo_set: self.logo_set,
        })
    }
}
