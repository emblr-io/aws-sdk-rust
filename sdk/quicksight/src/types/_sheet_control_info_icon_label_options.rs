// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A control to display info icons for filters and parameters.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SheetControlInfoIconLabelOptions {
    /// <p>The visibility configuration of info icon label options.</p>
    pub visibility: ::std::option::Option<crate::types::Visibility>,
    /// <p>The text content of info icon.</p>
    pub info_icon_text: ::std::option::Option<::std::string::String>,
}
impl SheetControlInfoIconLabelOptions {
    /// <p>The visibility configuration of info icon label options.</p>
    pub fn visibility(&self) -> ::std::option::Option<&crate::types::Visibility> {
        self.visibility.as_ref()
    }
    /// <p>The text content of info icon.</p>
    pub fn info_icon_text(&self) -> ::std::option::Option<&str> {
        self.info_icon_text.as_deref()
    }
}
impl SheetControlInfoIconLabelOptions {
    /// Creates a new builder-style object to manufacture [`SheetControlInfoIconLabelOptions`](crate::types::SheetControlInfoIconLabelOptions).
    pub fn builder() -> crate::types::builders::SheetControlInfoIconLabelOptionsBuilder {
        crate::types::builders::SheetControlInfoIconLabelOptionsBuilder::default()
    }
}

/// A builder for [`SheetControlInfoIconLabelOptions`](crate::types::SheetControlInfoIconLabelOptions).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SheetControlInfoIconLabelOptionsBuilder {
    pub(crate) visibility: ::std::option::Option<crate::types::Visibility>,
    pub(crate) info_icon_text: ::std::option::Option<::std::string::String>,
}
impl SheetControlInfoIconLabelOptionsBuilder {
    /// <p>The visibility configuration of info icon label options.</p>
    pub fn visibility(mut self, input: crate::types::Visibility) -> Self {
        self.visibility = ::std::option::Option::Some(input);
        self
    }
    /// <p>The visibility configuration of info icon label options.</p>
    pub fn set_visibility(mut self, input: ::std::option::Option<crate::types::Visibility>) -> Self {
        self.visibility = input;
        self
    }
    /// <p>The visibility configuration of info icon label options.</p>
    pub fn get_visibility(&self) -> &::std::option::Option<crate::types::Visibility> {
        &self.visibility
    }
    /// <p>The text content of info icon.</p>
    pub fn info_icon_text(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.info_icon_text = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The text content of info icon.</p>
    pub fn set_info_icon_text(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.info_icon_text = input;
        self
    }
    /// <p>The text content of info icon.</p>
    pub fn get_info_icon_text(&self) -> &::std::option::Option<::std::string::String> {
        &self.info_icon_text
    }
    /// Consumes the builder and constructs a [`SheetControlInfoIconLabelOptions`](crate::types::SheetControlInfoIconLabelOptions).
    pub fn build(self) -> crate::types::SheetControlInfoIconLabelOptions {
        crate::types::SheetControlInfoIconLabelOptions {
            visibility: self.visibility,
            info_icon_text: self.info_icon_text,
        }
    }
}
