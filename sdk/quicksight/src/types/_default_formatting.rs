// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A structure that represents a default formatting definition.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DefaultFormatting {
    /// <p>The display format. Valid values for this structure are <code>AUTO</code>, <code>PERCENT</code>, <code>CURRENCY</code>, <code>NUMBER</code>, <code>DATE</code>, and <code>STRING</code>.</p>
    pub display_format: ::std::option::Option<crate::types::DisplayFormat>,
    /// <p>The additional options for display formatting.</p>
    pub display_format_options: ::std::option::Option<crate::types::DisplayFormatOptions>,
}
impl DefaultFormatting {
    /// <p>The display format. Valid values for this structure are <code>AUTO</code>, <code>PERCENT</code>, <code>CURRENCY</code>, <code>NUMBER</code>, <code>DATE</code>, and <code>STRING</code>.</p>
    pub fn display_format(&self) -> ::std::option::Option<&crate::types::DisplayFormat> {
        self.display_format.as_ref()
    }
    /// <p>The additional options for display formatting.</p>
    pub fn display_format_options(&self) -> ::std::option::Option<&crate::types::DisplayFormatOptions> {
        self.display_format_options.as_ref()
    }
}
impl DefaultFormatting {
    /// Creates a new builder-style object to manufacture [`DefaultFormatting`](crate::types::DefaultFormatting).
    pub fn builder() -> crate::types::builders::DefaultFormattingBuilder {
        crate::types::builders::DefaultFormattingBuilder::default()
    }
}

/// A builder for [`DefaultFormatting`](crate::types::DefaultFormatting).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DefaultFormattingBuilder {
    pub(crate) display_format: ::std::option::Option<crate::types::DisplayFormat>,
    pub(crate) display_format_options: ::std::option::Option<crate::types::DisplayFormatOptions>,
}
impl DefaultFormattingBuilder {
    /// <p>The display format. Valid values for this structure are <code>AUTO</code>, <code>PERCENT</code>, <code>CURRENCY</code>, <code>NUMBER</code>, <code>DATE</code>, and <code>STRING</code>.</p>
    pub fn display_format(mut self, input: crate::types::DisplayFormat) -> Self {
        self.display_format = ::std::option::Option::Some(input);
        self
    }
    /// <p>The display format. Valid values for this structure are <code>AUTO</code>, <code>PERCENT</code>, <code>CURRENCY</code>, <code>NUMBER</code>, <code>DATE</code>, and <code>STRING</code>.</p>
    pub fn set_display_format(mut self, input: ::std::option::Option<crate::types::DisplayFormat>) -> Self {
        self.display_format = input;
        self
    }
    /// <p>The display format. Valid values for this structure are <code>AUTO</code>, <code>PERCENT</code>, <code>CURRENCY</code>, <code>NUMBER</code>, <code>DATE</code>, and <code>STRING</code>.</p>
    pub fn get_display_format(&self) -> &::std::option::Option<crate::types::DisplayFormat> {
        &self.display_format
    }
    /// <p>The additional options for display formatting.</p>
    pub fn display_format_options(mut self, input: crate::types::DisplayFormatOptions) -> Self {
        self.display_format_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>The additional options for display formatting.</p>
    pub fn set_display_format_options(mut self, input: ::std::option::Option<crate::types::DisplayFormatOptions>) -> Self {
        self.display_format_options = input;
        self
    }
    /// <p>The additional options for display formatting.</p>
    pub fn get_display_format_options(&self) -> &::std::option::Option<crate::types::DisplayFormatOptions> {
        &self.display_format_options
    }
    /// Consumes the builder and constructs a [`DefaultFormatting`](crate::types::DefaultFormatting).
    pub fn build(self) -> crate::types::DefaultFormatting {
        crate::types::DefaultFormatting {
            display_format: self.display_format,
            display_format_options: self.display_format_options,
        }
    }
}
