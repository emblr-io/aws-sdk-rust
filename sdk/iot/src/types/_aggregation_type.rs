// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The type of aggregation queries.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AggregationType {
    /// <p>The name of the aggregation type.</p>
    pub name: crate::types::AggregationTypeName,
    /// <p>A list of the values of aggregation types.</p>
    pub values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl AggregationType {
    /// <p>The name of the aggregation type.</p>
    pub fn name(&self) -> &crate::types::AggregationTypeName {
        &self.name
    }
    /// <p>A list of the values of aggregation types.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.values.is_none()`.
    pub fn values(&self) -> &[::std::string::String] {
        self.values.as_deref().unwrap_or_default()
    }
}
impl AggregationType {
    /// Creates a new builder-style object to manufacture [`AggregationType`](crate::types::AggregationType).
    pub fn builder() -> crate::types::builders::AggregationTypeBuilder {
        crate::types::builders::AggregationTypeBuilder::default()
    }
}

/// A builder for [`AggregationType`](crate::types::AggregationType).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AggregationTypeBuilder {
    pub(crate) name: ::std::option::Option<crate::types::AggregationTypeName>,
    pub(crate) values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl AggregationTypeBuilder {
    /// <p>The name of the aggregation type.</p>
    /// This field is required.
    pub fn name(mut self, input: crate::types::AggregationTypeName) -> Self {
        self.name = ::std::option::Option::Some(input);
        self
    }
    /// <p>The name of the aggregation type.</p>
    pub fn set_name(mut self, input: ::std::option::Option<crate::types::AggregationTypeName>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the aggregation type.</p>
    pub fn get_name(&self) -> &::std::option::Option<crate::types::AggregationTypeName> {
        &self.name
    }
    /// Appends an item to `values`.
    ///
    /// To override the contents of this collection use [`set_values`](Self::set_values).
    ///
    /// <p>A list of the values of aggregation types.</p>
    pub fn values(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.values.unwrap_or_default();
        v.push(input.into());
        self.values = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of the values of aggregation types.</p>
    pub fn set_values(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.values = input;
        self
    }
    /// <p>A list of the values of aggregation types.</p>
    pub fn get_values(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.values
    }
    /// Consumes the builder and constructs a [`AggregationType`](crate::types::AggregationType).
    /// This method will fail if any of the following fields are not set:
    /// - [`name`](crate::types::builders::AggregationTypeBuilder::name)
    pub fn build(self) -> ::std::result::Result<crate::types::AggregationType, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::AggregationType {
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building AggregationType",
                )
            })?,
            values: self.values,
        })
    }
}
