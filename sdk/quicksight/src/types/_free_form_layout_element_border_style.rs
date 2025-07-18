// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The background style configuration of a free-form layout element.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FreeFormLayoutElementBorderStyle {
    /// <p>The border visibility of a free-form layout element.</p>
    pub visibility: ::std::option::Option<crate::types::Visibility>,
    /// <p>The border color of a free-form layout element.</p>
    pub color: ::std::option::Option<::std::string::String>,
}
impl FreeFormLayoutElementBorderStyle {
    /// <p>The border visibility of a free-form layout element.</p>
    pub fn visibility(&self) -> ::std::option::Option<&crate::types::Visibility> {
        self.visibility.as_ref()
    }
    /// <p>The border color of a free-form layout element.</p>
    pub fn color(&self) -> ::std::option::Option<&str> {
        self.color.as_deref()
    }
}
impl FreeFormLayoutElementBorderStyle {
    /// Creates a new builder-style object to manufacture [`FreeFormLayoutElementBorderStyle`](crate::types::FreeFormLayoutElementBorderStyle).
    pub fn builder() -> crate::types::builders::FreeFormLayoutElementBorderStyleBuilder {
        crate::types::builders::FreeFormLayoutElementBorderStyleBuilder::default()
    }
}

/// A builder for [`FreeFormLayoutElementBorderStyle`](crate::types::FreeFormLayoutElementBorderStyle).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FreeFormLayoutElementBorderStyleBuilder {
    pub(crate) visibility: ::std::option::Option<crate::types::Visibility>,
    pub(crate) color: ::std::option::Option<::std::string::String>,
}
impl FreeFormLayoutElementBorderStyleBuilder {
    /// <p>The border visibility of a free-form layout element.</p>
    pub fn visibility(mut self, input: crate::types::Visibility) -> Self {
        self.visibility = ::std::option::Option::Some(input);
        self
    }
    /// <p>The border visibility of a free-form layout element.</p>
    pub fn set_visibility(mut self, input: ::std::option::Option<crate::types::Visibility>) -> Self {
        self.visibility = input;
        self
    }
    /// <p>The border visibility of a free-form layout element.</p>
    pub fn get_visibility(&self) -> &::std::option::Option<crate::types::Visibility> {
        &self.visibility
    }
    /// <p>The border color of a free-form layout element.</p>
    pub fn color(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.color = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The border color of a free-form layout element.</p>
    pub fn set_color(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.color = input;
        self
    }
    /// <p>The border color of a free-form layout element.</p>
    pub fn get_color(&self) -> &::std::option::Option<::std::string::String> {
        &self.color
    }
    /// Consumes the builder and constructs a [`FreeFormLayoutElementBorderStyle`](crate::types::FreeFormLayoutElementBorderStyle).
    pub fn build(self) -> crate::types::FreeFormLayoutElementBorderStyle {
        crate::types::FreeFormLayoutElementBorderStyle {
            visibility: self.visibility,
            color: self.color,
        }
    }
}
