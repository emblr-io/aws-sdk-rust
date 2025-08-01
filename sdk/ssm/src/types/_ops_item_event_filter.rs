// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a filter for a specific list of OpsItem events. You can filter event information by using tags. You specify tags by using a key-value pair mapping.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct OpsItemEventFilter {
    /// <p>The name of the filter key. Currently, the only supported value is <code>OpsItemId</code>.</p>
    pub key: crate::types::OpsItemEventFilterKey,
    /// <p>The values for the filter, consisting of one or more OpsItem IDs.</p>
    pub values: ::std::vec::Vec<::std::string::String>,
    /// <p>The operator used by the filter call. Currently, the only supported value is <code>Equal</code>.</p>
    pub operator: crate::types::OpsItemEventFilterOperator,
}
impl OpsItemEventFilter {
    /// <p>The name of the filter key. Currently, the only supported value is <code>OpsItemId</code>.</p>
    pub fn key(&self) -> &crate::types::OpsItemEventFilterKey {
        &self.key
    }
    /// <p>The values for the filter, consisting of one or more OpsItem IDs.</p>
    pub fn values(&self) -> &[::std::string::String] {
        use std::ops::Deref;
        self.values.deref()
    }
    /// <p>The operator used by the filter call. Currently, the only supported value is <code>Equal</code>.</p>
    pub fn operator(&self) -> &crate::types::OpsItemEventFilterOperator {
        &self.operator
    }
}
impl OpsItemEventFilter {
    /// Creates a new builder-style object to manufacture [`OpsItemEventFilter`](crate::types::OpsItemEventFilter).
    pub fn builder() -> crate::types::builders::OpsItemEventFilterBuilder {
        crate::types::builders::OpsItemEventFilterBuilder::default()
    }
}

/// A builder for [`OpsItemEventFilter`](crate::types::OpsItemEventFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct OpsItemEventFilterBuilder {
    pub(crate) key: ::std::option::Option<crate::types::OpsItemEventFilterKey>,
    pub(crate) values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) operator: ::std::option::Option<crate::types::OpsItemEventFilterOperator>,
}
impl OpsItemEventFilterBuilder {
    /// <p>The name of the filter key. Currently, the only supported value is <code>OpsItemId</code>.</p>
    /// This field is required.
    pub fn key(mut self, input: crate::types::OpsItemEventFilterKey) -> Self {
        self.key = ::std::option::Option::Some(input);
        self
    }
    /// <p>The name of the filter key. Currently, the only supported value is <code>OpsItemId</code>.</p>
    pub fn set_key(mut self, input: ::std::option::Option<crate::types::OpsItemEventFilterKey>) -> Self {
        self.key = input;
        self
    }
    /// <p>The name of the filter key. Currently, the only supported value is <code>OpsItemId</code>.</p>
    pub fn get_key(&self) -> &::std::option::Option<crate::types::OpsItemEventFilterKey> {
        &self.key
    }
    /// Appends an item to `values`.
    ///
    /// To override the contents of this collection use [`set_values`](Self::set_values).
    ///
    /// <p>The values for the filter, consisting of one or more OpsItem IDs.</p>
    pub fn values(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.values.unwrap_or_default();
        v.push(input.into());
        self.values = ::std::option::Option::Some(v);
        self
    }
    /// <p>The values for the filter, consisting of one or more OpsItem IDs.</p>
    pub fn set_values(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.values = input;
        self
    }
    /// <p>The values for the filter, consisting of one or more OpsItem IDs.</p>
    pub fn get_values(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.values
    }
    /// <p>The operator used by the filter call. Currently, the only supported value is <code>Equal</code>.</p>
    /// This field is required.
    pub fn operator(mut self, input: crate::types::OpsItemEventFilterOperator) -> Self {
        self.operator = ::std::option::Option::Some(input);
        self
    }
    /// <p>The operator used by the filter call. Currently, the only supported value is <code>Equal</code>.</p>
    pub fn set_operator(mut self, input: ::std::option::Option<crate::types::OpsItemEventFilterOperator>) -> Self {
        self.operator = input;
        self
    }
    /// <p>The operator used by the filter call. Currently, the only supported value is <code>Equal</code>.</p>
    pub fn get_operator(&self) -> &::std::option::Option<crate::types::OpsItemEventFilterOperator> {
        &self.operator
    }
    /// Consumes the builder and constructs a [`OpsItemEventFilter`](crate::types::OpsItemEventFilter).
    /// This method will fail if any of the following fields are not set:
    /// - [`key`](crate::types::builders::OpsItemEventFilterBuilder::key)
    /// - [`values`](crate::types::builders::OpsItemEventFilterBuilder::values)
    /// - [`operator`](crate::types::builders::OpsItemEventFilterBuilder::operator)
    pub fn build(self) -> ::std::result::Result<crate::types::OpsItemEventFilter, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::OpsItemEventFilter {
            key: self.key.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "key",
                    "key was not specified but it is required when building OpsItemEventFilter",
                )
            })?,
            values: self.values.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "values",
                    "values was not specified but it is required when building OpsItemEventFilter",
                )
            })?,
            operator: self.operator.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "operator",
                    "operator was not specified but it is required when building OpsItemEventFilter",
                )
            })?,
        })
    }
}
