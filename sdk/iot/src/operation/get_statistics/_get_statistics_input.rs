// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetStatisticsInput {
    /// <p>The name of the index to search. The default value is <code>AWS_Things</code>.</p>
    pub index_name: ::std::option::Option<::std::string::String>,
    /// <p>The query used to search. You can specify "*" for the query string to get the count of all indexed things in your Amazon Web Services account.</p>
    pub query_string: ::std::option::Option<::std::string::String>,
    /// <p>The aggregation field name.</p>
    pub aggregation_field: ::std::option::Option<::std::string::String>,
    /// <p>The version of the query used to search.</p>
    pub query_version: ::std::option::Option<::std::string::String>,
}
impl GetStatisticsInput {
    /// <p>The name of the index to search. The default value is <code>AWS_Things</code>.</p>
    pub fn index_name(&self) -> ::std::option::Option<&str> {
        self.index_name.as_deref()
    }
    /// <p>The query used to search. You can specify "*" for the query string to get the count of all indexed things in your Amazon Web Services account.</p>
    pub fn query_string(&self) -> ::std::option::Option<&str> {
        self.query_string.as_deref()
    }
    /// <p>The aggregation field name.</p>
    pub fn aggregation_field(&self) -> ::std::option::Option<&str> {
        self.aggregation_field.as_deref()
    }
    /// <p>The version of the query used to search.</p>
    pub fn query_version(&self) -> ::std::option::Option<&str> {
        self.query_version.as_deref()
    }
}
impl GetStatisticsInput {
    /// Creates a new builder-style object to manufacture [`GetStatisticsInput`](crate::operation::get_statistics::GetStatisticsInput).
    pub fn builder() -> crate::operation::get_statistics::builders::GetStatisticsInputBuilder {
        crate::operation::get_statistics::builders::GetStatisticsInputBuilder::default()
    }
}

/// A builder for [`GetStatisticsInput`](crate::operation::get_statistics::GetStatisticsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetStatisticsInputBuilder {
    pub(crate) index_name: ::std::option::Option<::std::string::String>,
    pub(crate) query_string: ::std::option::Option<::std::string::String>,
    pub(crate) aggregation_field: ::std::option::Option<::std::string::String>,
    pub(crate) query_version: ::std::option::Option<::std::string::String>,
}
impl GetStatisticsInputBuilder {
    /// <p>The name of the index to search. The default value is <code>AWS_Things</code>.</p>
    pub fn index_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.index_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the index to search. The default value is <code>AWS_Things</code>.</p>
    pub fn set_index_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.index_name = input;
        self
    }
    /// <p>The name of the index to search. The default value is <code>AWS_Things</code>.</p>
    pub fn get_index_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.index_name
    }
    /// <p>The query used to search. You can specify "*" for the query string to get the count of all indexed things in your Amazon Web Services account.</p>
    /// This field is required.
    pub fn query_string(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.query_string = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The query used to search. You can specify "*" for the query string to get the count of all indexed things in your Amazon Web Services account.</p>
    pub fn set_query_string(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.query_string = input;
        self
    }
    /// <p>The query used to search. You can specify "*" for the query string to get the count of all indexed things in your Amazon Web Services account.</p>
    pub fn get_query_string(&self) -> &::std::option::Option<::std::string::String> {
        &self.query_string
    }
    /// <p>The aggregation field name.</p>
    pub fn aggregation_field(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.aggregation_field = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The aggregation field name.</p>
    pub fn set_aggregation_field(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.aggregation_field = input;
        self
    }
    /// <p>The aggregation field name.</p>
    pub fn get_aggregation_field(&self) -> &::std::option::Option<::std::string::String> {
        &self.aggregation_field
    }
    /// <p>The version of the query used to search.</p>
    pub fn query_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.query_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the query used to search.</p>
    pub fn set_query_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.query_version = input;
        self
    }
    /// <p>The version of the query used to search.</p>
    pub fn get_query_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.query_version
    }
    /// Consumes the builder and constructs a [`GetStatisticsInput`](crate::operation::get_statistics::GetStatisticsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_statistics::GetStatisticsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_statistics::GetStatisticsInput {
            index_name: self.index_name,
            query_string: self.query_string,
            aggregation_field: self.aggregation_field,
            query_version: self.query_version,
        })
    }
}
