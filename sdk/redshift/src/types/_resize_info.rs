// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a resize operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ResizeInfo {
    /// <p>Returns the value <code>ClassicResize</code>.</p>
    pub resize_type: ::std::option::Option<::std::string::String>,
    /// <p>A boolean value indicating if the resize operation can be cancelled.</p>
    pub allow_cancel_resize: ::std::option::Option<bool>,
}
impl ResizeInfo {
    /// <p>Returns the value <code>ClassicResize</code>.</p>
    pub fn resize_type(&self) -> ::std::option::Option<&str> {
        self.resize_type.as_deref()
    }
    /// <p>A boolean value indicating if the resize operation can be cancelled.</p>
    pub fn allow_cancel_resize(&self) -> ::std::option::Option<bool> {
        self.allow_cancel_resize
    }
}
impl ResizeInfo {
    /// Creates a new builder-style object to manufacture [`ResizeInfo`](crate::types::ResizeInfo).
    pub fn builder() -> crate::types::builders::ResizeInfoBuilder {
        crate::types::builders::ResizeInfoBuilder::default()
    }
}

/// A builder for [`ResizeInfo`](crate::types::ResizeInfo).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ResizeInfoBuilder {
    pub(crate) resize_type: ::std::option::Option<::std::string::String>,
    pub(crate) allow_cancel_resize: ::std::option::Option<bool>,
}
impl ResizeInfoBuilder {
    /// <p>Returns the value <code>ClassicResize</code>.</p>
    pub fn resize_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resize_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Returns the value <code>ClassicResize</code>.</p>
    pub fn set_resize_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resize_type = input;
        self
    }
    /// <p>Returns the value <code>ClassicResize</code>.</p>
    pub fn get_resize_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.resize_type
    }
    /// <p>A boolean value indicating if the resize operation can be cancelled.</p>
    pub fn allow_cancel_resize(mut self, input: bool) -> Self {
        self.allow_cancel_resize = ::std::option::Option::Some(input);
        self
    }
    /// <p>A boolean value indicating if the resize operation can be cancelled.</p>
    pub fn set_allow_cancel_resize(mut self, input: ::std::option::Option<bool>) -> Self {
        self.allow_cancel_resize = input;
        self
    }
    /// <p>A boolean value indicating if the resize operation can be cancelled.</p>
    pub fn get_allow_cancel_resize(&self) -> &::std::option::Option<bool> {
        &self.allow_cancel_resize
    }
    /// Consumes the builder and constructs a [`ResizeInfo`](crate::types::ResizeInfo).
    pub fn build(self) -> crate::types::ResizeInfo {
        crate::types::ResizeInfo {
            resize_type: self.resize_type,
            allow_cancel_resize: self.allow_cancel_resize,
        }
    }
}
