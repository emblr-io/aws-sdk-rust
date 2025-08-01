// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A <code>GroupSearchFilter</code> object that you want to apply to your search.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GroupSearchFilter {
    /// <p>The comparison operator that you want to use as a filter, for example <code>"Operator": "StartsWith"</code>. Currently, the only supported operator is <code>StartsWith</code>.</p>
    pub operator: crate::types::GroupFilterOperator,
    /// <p>The name of the value that you want to use as a filter, for example <code>"Name": "GROUP_NAME"</code>. Currently, the only supported name is <code>GROUP_NAME</code>.</p>
    pub name: crate::types::GroupFilterAttribute,
    /// <p>The value of the named item, in this case <code>GROUP_NAME</code>, that you want to use as a filter.</p>
    pub value: ::std::string::String,
}
impl GroupSearchFilter {
    /// <p>The comparison operator that you want to use as a filter, for example <code>"Operator": "StartsWith"</code>. Currently, the only supported operator is <code>StartsWith</code>.</p>
    pub fn operator(&self) -> &crate::types::GroupFilterOperator {
        &self.operator
    }
    /// <p>The name of the value that you want to use as a filter, for example <code>"Name": "GROUP_NAME"</code>. Currently, the only supported name is <code>GROUP_NAME</code>.</p>
    pub fn name(&self) -> &crate::types::GroupFilterAttribute {
        &self.name
    }
    /// <p>The value of the named item, in this case <code>GROUP_NAME</code>, that you want to use as a filter.</p>
    pub fn value(&self) -> &str {
        use std::ops::Deref;
        self.value.deref()
    }
}
impl GroupSearchFilter {
    /// Creates a new builder-style object to manufacture [`GroupSearchFilter`](crate::types::GroupSearchFilter).
    pub fn builder() -> crate::types::builders::GroupSearchFilterBuilder {
        crate::types::builders::GroupSearchFilterBuilder::default()
    }
}

/// A builder for [`GroupSearchFilter`](crate::types::GroupSearchFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GroupSearchFilterBuilder {
    pub(crate) operator: ::std::option::Option<crate::types::GroupFilterOperator>,
    pub(crate) name: ::std::option::Option<crate::types::GroupFilterAttribute>,
    pub(crate) value: ::std::option::Option<::std::string::String>,
}
impl GroupSearchFilterBuilder {
    /// <p>The comparison operator that you want to use as a filter, for example <code>"Operator": "StartsWith"</code>. Currently, the only supported operator is <code>StartsWith</code>.</p>
    /// This field is required.
    pub fn operator(mut self, input: crate::types::GroupFilterOperator) -> Self {
        self.operator = ::std::option::Option::Some(input);
        self
    }
    /// <p>The comparison operator that you want to use as a filter, for example <code>"Operator": "StartsWith"</code>. Currently, the only supported operator is <code>StartsWith</code>.</p>
    pub fn set_operator(mut self, input: ::std::option::Option<crate::types::GroupFilterOperator>) -> Self {
        self.operator = input;
        self
    }
    /// <p>The comparison operator that you want to use as a filter, for example <code>"Operator": "StartsWith"</code>. Currently, the only supported operator is <code>StartsWith</code>.</p>
    pub fn get_operator(&self) -> &::std::option::Option<crate::types::GroupFilterOperator> {
        &self.operator
    }
    /// <p>The name of the value that you want to use as a filter, for example <code>"Name": "GROUP_NAME"</code>. Currently, the only supported name is <code>GROUP_NAME</code>.</p>
    /// This field is required.
    pub fn name(mut self, input: crate::types::GroupFilterAttribute) -> Self {
        self.name = ::std::option::Option::Some(input);
        self
    }
    /// <p>The name of the value that you want to use as a filter, for example <code>"Name": "GROUP_NAME"</code>. Currently, the only supported name is <code>GROUP_NAME</code>.</p>
    pub fn set_name(mut self, input: ::std::option::Option<crate::types::GroupFilterAttribute>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the value that you want to use as a filter, for example <code>"Name": "GROUP_NAME"</code>. Currently, the only supported name is <code>GROUP_NAME</code>.</p>
    pub fn get_name(&self) -> &::std::option::Option<crate::types::GroupFilterAttribute> {
        &self.name
    }
    /// <p>The value of the named item, in this case <code>GROUP_NAME</code>, that you want to use as a filter.</p>
    /// This field is required.
    pub fn value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The value of the named item, in this case <code>GROUP_NAME</code>, that you want to use as a filter.</p>
    pub fn set_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.value = input;
        self
    }
    /// <p>The value of the named item, in this case <code>GROUP_NAME</code>, that you want to use as a filter.</p>
    pub fn get_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.value
    }
    /// Consumes the builder and constructs a [`GroupSearchFilter`](crate::types::GroupSearchFilter).
    /// This method will fail if any of the following fields are not set:
    /// - [`operator`](crate::types::builders::GroupSearchFilterBuilder::operator)
    /// - [`name`](crate::types::builders::GroupSearchFilterBuilder::name)
    /// - [`value`](crate::types::builders::GroupSearchFilterBuilder::value)
    pub fn build(self) -> ::std::result::Result<crate::types::GroupSearchFilter, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::GroupSearchFilter {
            operator: self.operator.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "operator",
                    "operator was not specified but it is required when building GroupSearchFilter",
                )
            })?,
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building GroupSearchFilter",
                )
            })?,
            value: self.value.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "value",
                    "value was not specified but it is required when building GroupSearchFilter",
                )
            })?,
        })
    }
}
