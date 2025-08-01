// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Indicates the sorting order of the fields in the metrics.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Sort {
    /// <p>Indicates the order in which you want to sort the metrics. By default, the list is sorted in ascending order. To sort the list in descending order, set this field to False.</p>
    pub field: ::std::string::String,
    /// <p>Indicates the name or identifier of the field or attribute that should be used as the basis for sorting the metrics.</p>
    pub ascending: ::std::option::Option<bool>,
}
impl Sort {
    /// <p>Indicates the order in which you want to sort the metrics. By default, the list is sorted in ascending order. To sort the list in descending order, set this field to False.</p>
    pub fn field(&self) -> &str {
        use std::ops::Deref;
        self.field.deref()
    }
    /// <p>Indicates the name or identifier of the field or attribute that should be used as the basis for sorting the metrics.</p>
    pub fn ascending(&self) -> ::std::option::Option<bool> {
        self.ascending
    }
}
impl Sort {
    /// Creates a new builder-style object to manufacture [`Sort`](crate::types::Sort).
    pub fn builder() -> crate::types::builders::SortBuilder {
        crate::types::builders::SortBuilder::default()
    }
}

/// A builder for [`Sort`](crate::types::Sort).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SortBuilder {
    pub(crate) field: ::std::option::Option<::std::string::String>,
    pub(crate) ascending: ::std::option::Option<bool>,
}
impl SortBuilder {
    /// <p>Indicates the order in which you want to sort the metrics. By default, the list is sorted in ascending order. To sort the list in descending order, set this field to False.</p>
    /// This field is required.
    pub fn field(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.field = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Indicates the order in which you want to sort the metrics. By default, the list is sorted in ascending order. To sort the list in descending order, set this field to False.</p>
    pub fn set_field(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.field = input;
        self
    }
    /// <p>Indicates the order in which you want to sort the metrics. By default, the list is sorted in ascending order. To sort the list in descending order, set this field to False.</p>
    pub fn get_field(&self) -> &::std::option::Option<::std::string::String> {
        &self.field
    }
    /// <p>Indicates the name or identifier of the field or attribute that should be used as the basis for sorting the metrics.</p>
    pub fn ascending(mut self, input: bool) -> Self {
        self.ascending = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates the name or identifier of the field or attribute that should be used as the basis for sorting the metrics.</p>
    pub fn set_ascending(mut self, input: ::std::option::Option<bool>) -> Self {
        self.ascending = input;
        self
    }
    /// <p>Indicates the name or identifier of the field or attribute that should be used as the basis for sorting the metrics.</p>
    pub fn get_ascending(&self) -> &::std::option::Option<bool> {
        &self.ascending
    }
    /// Consumes the builder and constructs a [`Sort`](crate::types::Sort).
    /// This method will fail if any of the following fields are not set:
    /// - [`field`](crate::types::builders::SortBuilder::field)
    pub fn build(self) -> ::std::result::Result<crate::types::Sort, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Sort {
            field: self.field.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "field",
                    "field was not specified but it is required when building Sort",
                )
            })?,
            ascending: self.ascending,
        })
    }
}
