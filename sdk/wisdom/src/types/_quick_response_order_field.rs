// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The quick response fields to order the quick response query results by.</p>
/// <p>The following is the list of supported field names.</p>
/// <ul>
/// <li>
/// <p>name</p></li>
/// <li>
/// <p>description</p></li>
/// <li>
/// <p>shortcutKey</p></li>
/// <li>
/// <p>isActive</p></li>
/// <li>
/// <p>channels</p></li>
/// <li>
/// <p>language</p></li>
/// <li>
/// <p>contentType</p></li>
/// <li>
/// <p>createdTime</p></li>
/// <li>
/// <p>lastModifiedTime</p></li>
/// <li>
/// <p>lastModifiedBy</p></li>
/// <li>
/// <p>groupingConfiguration.criteria</p></li>
/// <li>
/// <p>groupingConfiguration.values</p></li>
/// </ul>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct QuickResponseOrderField {
    /// <p>The name of the attribute to order the quick response query results by.</p>
    pub name: ::std::string::String,
    /// <p>The order at which the quick responses are sorted by.</p>
    pub order: ::std::option::Option<crate::types::Order>,
}
impl QuickResponseOrderField {
    /// <p>The name of the attribute to order the quick response query results by.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The order at which the quick responses are sorted by.</p>
    pub fn order(&self) -> ::std::option::Option<&crate::types::Order> {
        self.order.as_ref()
    }
}
impl QuickResponseOrderField {
    /// Creates a new builder-style object to manufacture [`QuickResponseOrderField`](crate::types::QuickResponseOrderField).
    pub fn builder() -> crate::types::builders::QuickResponseOrderFieldBuilder {
        crate::types::builders::QuickResponseOrderFieldBuilder::default()
    }
}

/// A builder for [`QuickResponseOrderField`](crate::types::QuickResponseOrderField).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct QuickResponseOrderFieldBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) order: ::std::option::Option<crate::types::Order>,
}
impl QuickResponseOrderFieldBuilder {
    /// <p>The name of the attribute to order the quick response query results by.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the attribute to order the quick response query results by.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the attribute to order the quick response query results by.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The order at which the quick responses are sorted by.</p>
    pub fn order(mut self, input: crate::types::Order) -> Self {
        self.order = ::std::option::Option::Some(input);
        self
    }
    /// <p>The order at which the quick responses are sorted by.</p>
    pub fn set_order(mut self, input: ::std::option::Option<crate::types::Order>) -> Self {
        self.order = input;
        self
    }
    /// <p>The order at which the quick responses are sorted by.</p>
    pub fn get_order(&self) -> &::std::option::Option<crate::types::Order> {
        &self.order
    }
    /// Consumes the builder and constructs a [`QuickResponseOrderField`](crate::types::QuickResponseOrderField).
    /// This method will fail if any of the following fields are not set:
    /// - [`name`](crate::types::builders::QuickResponseOrderFieldBuilder::name)
    pub fn build(self) -> ::std::result::Result<crate::types::QuickResponseOrderField, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::QuickResponseOrderField {
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building QuickResponseOrderField",
                )
            })?,
            order: self.order,
        })
    }
}
