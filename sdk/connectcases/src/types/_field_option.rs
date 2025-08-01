// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Object for field Options information.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FieldOption {
    /// <p><code>FieldOptionName</code> has max length 100 and disallows trailing spaces.</p>
    pub name: ::std::string::String,
    /// <p><code>FieldOptionValue</code> has max length 100 and must be alphanumeric with hyphens and underscores.</p>
    pub value: ::std::string::String,
    /// <p>Describes whether the <code>FieldOption</code> is active (displayed) or inactive.</p>
    pub active: bool,
}
impl FieldOption {
    /// <p><code>FieldOptionName</code> has max length 100 and disallows trailing spaces.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p><code>FieldOptionValue</code> has max length 100 and must be alphanumeric with hyphens and underscores.</p>
    pub fn value(&self) -> &str {
        use std::ops::Deref;
        self.value.deref()
    }
    /// <p>Describes whether the <code>FieldOption</code> is active (displayed) or inactive.</p>
    pub fn active(&self) -> bool {
        self.active
    }
}
impl FieldOption {
    /// Creates a new builder-style object to manufacture [`FieldOption`](crate::types::FieldOption).
    pub fn builder() -> crate::types::builders::FieldOptionBuilder {
        crate::types::builders::FieldOptionBuilder::default()
    }
}

/// A builder for [`FieldOption`](crate::types::FieldOption).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FieldOptionBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) value: ::std::option::Option<::std::string::String>,
    pub(crate) active: ::std::option::Option<bool>,
}
impl FieldOptionBuilder {
    /// <p><code>FieldOptionName</code> has max length 100 and disallows trailing spaces.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p><code>FieldOptionName</code> has max length 100 and disallows trailing spaces.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p><code>FieldOptionName</code> has max length 100 and disallows trailing spaces.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p><code>FieldOptionValue</code> has max length 100 and must be alphanumeric with hyphens and underscores.</p>
    /// This field is required.
    pub fn value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p><code>FieldOptionValue</code> has max length 100 and must be alphanumeric with hyphens and underscores.</p>
    pub fn set_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.value = input;
        self
    }
    /// <p><code>FieldOptionValue</code> has max length 100 and must be alphanumeric with hyphens and underscores.</p>
    pub fn get_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.value
    }
    /// <p>Describes whether the <code>FieldOption</code> is active (displayed) or inactive.</p>
    /// This field is required.
    pub fn active(mut self, input: bool) -> Self {
        self.active = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes whether the <code>FieldOption</code> is active (displayed) or inactive.</p>
    pub fn set_active(mut self, input: ::std::option::Option<bool>) -> Self {
        self.active = input;
        self
    }
    /// <p>Describes whether the <code>FieldOption</code> is active (displayed) or inactive.</p>
    pub fn get_active(&self) -> &::std::option::Option<bool> {
        &self.active
    }
    /// Consumes the builder and constructs a [`FieldOption`](crate::types::FieldOption).
    /// This method will fail if any of the following fields are not set:
    /// - [`name`](crate::types::builders::FieldOptionBuilder::name)
    /// - [`value`](crate::types::builders::FieldOptionBuilder::value)
    /// - [`active`](crate::types::builders::FieldOptionBuilder::active)
    pub fn build(self) -> ::std::result::Result<crate::types::FieldOption, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::FieldOption {
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building FieldOption",
                )
            })?,
            value: self.value.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "value",
                    "value was not specified but it is required when building FieldOption",
                )
            })?,
            active: self.active.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "active",
                    "active was not specified but it is required when building FieldOption",
                )
            })?,
        })
    }
}
