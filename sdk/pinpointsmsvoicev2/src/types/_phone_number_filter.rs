// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The information for a phone number that meets a specified criteria.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PhoneNumberFilter {
    /// <p>The name of the attribute to filter on.</p>
    pub name: crate::types::PhoneNumberFilterName,
    /// <p>An array values to filter for.</p>
    pub values: ::std::vec::Vec<::std::string::String>,
}
impl PhoneNumberFilter {
    /// <p>The name of the attribute to filter on.</p>
    pub fn name(&self) -> &crate::types::PhoneNumberFilterName {
        &self.name
    }
    /// <p>An array values to filter for.</p>
    pub fn values(&self) -> &[::std::string::String] {
        use std::ops::Deref;
        self.values.deref()
    }
}
impl PhoneNumberFilter {
    /// Creates a new builder-style object to manufacture [`PhoneNumberFilter`](crate::types::PhoneNumberFilter).
    pub fn builder() -> crate::types::builders::PhoneNumberFilterBuilder {
        crate::types::builders::PhoneNumberFilterBuilder::default()
    }
}

/// A builder for [`PhoneNumberFilter`](crate::types::PhoneNumberFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PhoneNumberFilterBuilder {
    pub(crate) name: ::std::option::Option<crate::types::PhoneNumberFilterName>,
    pub(crate) values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl PhoneNumberFilterBuilder {
    /// <p>The name of the attribute to filter on.</p>
    /// This field is required.
    pub fn name(mut self, input: crate::types::PhoneNumberFilterName) -> Self {
        self.name = ::std::option::Option::Some(input);
        self
    }
    /// <p>The name of the attribute to filter on.</p>
    pub fn set_name(mut self, input: ::std::option::Option<crate::types::PhoneNumberFilterName>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the attribute to filter on.</p>
    pub fn get_name(&self) -> &::std::option::Option<crate::types::PhoneNumberFilterName> {
        &self.name
    }
    /// Appends an item to `values`.
    ///
    /// To override the contents of this collection use [`set_values`](Self::set_values).
    ///
    /// <p>An array values to filter for.</p>
    pub fn values(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.values.unwrap_or_default();
        v.push(input.into());
        self.values = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array values to filter for.</p>
    pub fn set_values(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.values = input;
        self
    }
    /// <p>An array values to filter for.</p>
    pub fn get_values(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.values
    }
    /// Consumes the builder and constructs a [`PhoneNumberFilter`](crate::types::PhoneNumberFilter).
    /// This method will fail if any of the following fields are not set:
    /// - [`name`](crate::types::builders::PhoneNumberFilterBuilder::name)
    /// - [`values`](crate::types::builders::PhoneNumberFilterBuilder::values)
    pub fn build(self) -> ::std::result::Result<crate::types::PhoneNumberFilter, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::PhoneNumberFilter {
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building PhoneNumberFilter",
                )
            })?,
            values: self.values.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "values",
                    "values was not specified but it is required when building PhoneNumberFilter",
                )
            })?,
        })
    }
}
