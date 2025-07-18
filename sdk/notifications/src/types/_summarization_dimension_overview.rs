// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides an overview of how data is summarized across different dimensions.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SummarizationDimensionOverview {
    /// <p>Name of the summarization dimension.</p>
    pub name: ::std::string::String,
    /// <p>Total number of occurrences for this dimension.</p>
    pub count: i32,
    /// <p>Indicates the sample values found within the dimension.</p>
    pub sample_values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl SummarizationDimensionOverview {
    /// <p>Name of the summarization dimension.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>Total number of occurrences for this dimension.</p>
    pub fn count(&self) -> i32 {
        self.count
    }
    /// <p>Indicates the sample values found within the dimension.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.sample_values.is_none()`.
    pub fn sample_values(&self) -> &[::std::string::String] {
        self.sample_values.as_deref().unwrap_or_default()
    }
}
impl SummarizationDimensionOverview {
    /// Creates a new builder-style object to manufacture [`SummarizationDimensionOverview`](crate::types::SummarizationDimensionOverview).
    pub fn builder() -> crate::types::builders::SummarizationDimensionOverviewBuilder {
        crate::types::builders::SummarizationDimensionOverviewBuilder::default()
    }
}

/// A builder for [`SummarizationDimensionOverview`](crate::types::SummarizationDimensionOverview).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SummarizationDimensionOverviewBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) count: ::std::option::Option<i32>,
    pub(crate) sample_values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl SummarizationDimensionOverviewBuilder {
    /// <p>Name of the summarization dimension.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name of the summarization dimension.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>Name of the summarization dimension.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>Total number of occurrences for this dimension.</p>
    /// This field is required.
    pub fn count(mut self, input: i32) -> Self {
        self.count = ::std::option::Option::Some(input);
        self
    }
    /// <p>Total number of occurrences for this dimension.</p>
    pub fn set_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.count = input;
        self
    }
    /// <p>Total number of occurrences for this dimension.</p>
    pub fn get_count(&self) -> &::std::option::Option<i32> {
        &self.count
    }
    /// Appends an item to `sample_values`.
    ///
    /// To override the contents of this collection use [`set_sample_values`](Self::set_sample_values).
    ///
    /// <p>Indicates the sample values found within the dimension.</p>
    pub fn sample_values(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.sample_values.unwrap_or_default();
        v.push(input.into());
        self.sample_values = ::std::option::Option::Some(v);
        self
    }
    /// <p>Indicates the sample values found within the dimension.</p>
    pub fn set_sample_values(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.sample_values = input;
        self
    }
    /// <p>Indicates the sample values found within the dimension.</p>
    pub fn get_sample_values(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.sample_values
    }
    /// Consumes the builder and constructs a [`SummarizationDimensionOverview`](crate::types::SummarizationDimensionOverview).
    /// This method will fail if any of the following fields are not set:
    /// - [`name`](crate::types::builders::SummarizationDimensionOverviewBuilder::name)
    /// - [`count`](crate::types::builders::SummarizationDimensionOverviewBuilder::count)
    pub fn build(self) -> ::std::result::Result<crate::types::SummarizationDimensionOverview, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::SummarizationDimensionOverview {
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building SummarizationDimensionOverview",
                )
            })?,
            count: self.count.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "count",
                    "count was not specified but it is required when building SummarizationDimensionOverview",
                )
            })?,
            sample_values: self.sample_values,
        })
    }
}
