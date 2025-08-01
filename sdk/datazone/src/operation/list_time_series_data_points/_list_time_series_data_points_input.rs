// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListTimeSeriesDataPointsInput {
    /// <p>The ID of the Amazon DataZone domain that houses the assets for which you want to list time series data points.</p>
    pub domain_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the asset for which you want to list data points.</p>
    pub entity_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The type of the asset for which you want to list data points.</p>
    pub entity_type: ::std::option::Option<crate::types::TimeSeriesEntityType>,
    /// <p>The name of the time series data points form.</p>
    pub form_name: ::std::option::Option<::std::string::String>,
    /// <p>The timestamp at which the data points that you want to list started.</p>
    pub started_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The timestamp at which the data points that you wanted to list ended.</p>
    pub ended_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>When the number of data points is greater than the default value for the MaxResults parameter, or if you explicitly specify a value for MaxResults that is less than the number of data points, the response includes a pagination token named NextToken. You can specify this NextToken value in a subsequent call to ListTimeSeriesDataPoints to list the next set of data points.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of data points to return in a single call to ListTimeSeriesDataPoints. When the number of data points to be listed is greater than the value of MaxResults, the response contains a NextToken value that you can use in a subsequent call to ListTimeSeriesDataPoints to list the next set of data points.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListTimeSeriesDataPointsInput {
    /// <p>The ID of the Amazon DataZone domain that houses the assets for which you want to list time series data points.</p>
    pub fn domain_identifier(&self) -> ::std::option::Option<&str> {
        self.domain_identifier.as_deref()
    }
    /// <p>The ID of the asset for which you want to list data points.</p>
    pub fn entity_identifier(&self) -> ::std::option::Option<&str> {
        self.entity_identifier.as_deref()
    }
    /// <p>The type of the asset for which you want to list data points.</p>
    pub fn entity_type(&self) -> ::std::option::Option<&crate::types::TimeSeriesEntityType> {
        self.entity_type.as_ref()
    }
    /// <p>The name of the time series data points form.</p>
    pub fn form_name(&self) -> ::std::option::Option<&str> {
        self.form_name.as_deref()
    }
    /// <p>The timestamp at which the data points that you want to list started.</p>
    pub fn started_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.started_at.as_ref()
    }
    /// <p>The timestamp at which the data points that you wanted to list ended.</p>
    pub fn ended_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.ended_at.as_ref()
    }
    /// <p>When the number of data points is greater than the default value for the MaxResults parameter, or if you explicitly specify a value for MaxResults that is less than the number of data points, the response includes a pagination token named NextToken. You can specify this NextToken value in a subsequent call to ListTimeSeriesDataPoints to list the next set of data points.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of data points to return in a single call to ListTimeSeriesDataPoints. When the number of data points to be listed is greater than the value of MaxResults, the response contains a NextToken value that you can use in a subsequent call to ListTimeSeriesDataPoints to list the next set of data points.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListTimeSeriesDataPointsInput {
    /// Creates a new builder-style object to manufacture [`ListTimeSeriesDataPointsInput`](crate::operation::list_time_series_data_points::ListTimeSeriesDataPointsInput).
    pub fn builder() -> crate::operation::list_time_series_data_points::builders::ListTimeSeriesDataPointsInputBuilder {
        crate::operation::list_time_series_data_points::builders::ListTimeSeriesDataPointsInputBuilder::default()
    }
}

/// A builder for [`ListTimeSeriesDataPointsInput`](crate::operation::list_time_series_data_points::ListTimeSeriesDataPointsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListTimeSeriesDataPointsInputBuilder {
    pub(crate) domain_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) entity_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) entity_type: ::std::option::Option<crate::types::TimeSeriesEntityType>,
    pub(crate) form_name: ::std::option::Option<::std::string::String>,
    pub(crate) started_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) ended_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListTimeSeriesDataPointsInputBuilder {
    /// <p>The ID of the Amazon DataZone domain that houses the assets for which you want to list time series data points.</p>
    /// This field is required.
    pub fn domain_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Amazon DataZone domain that houses the assets for which you want to list time series data points.</p>
    pub fn set_domain_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_identifier = input;
        self
    }
    /// <p>The ID of the Amazon DataZone domain that houses the assets for which you want to list time series data points.</p>
    pub fn get_domain_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_identifier
    }
    /// <p>The ID of the asset for which you want to list data points.</p>
    /// This field is required.
    pub fn entity_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.entity_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the asset for which you want to list data points.</p>
    pub fn set_entity_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.entity_identifier = input;
        self
    }
    /// <p>The ID of the asset for which you want to list data points.</p>
    pub fn get_entity_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.entity_identifier
    }
    /// <p>The type of the asset for which you want to list data points.</p>
    /// This field is required.
    pub fn entity_type(mut self, input: crate::types::TimeSeriesEntityType) -> Self {
        self.entity_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of the asset for which you want to list data points.</p>
    pub fn set_entity_type(mut self, input: ::std::option::Option<crate::types::TimeSeriesEntityType>) -> Self {
        self.entity_type = input;
        self
    }
    /// <p>The type of the asset for which you want to list data points.</p>
    pub fn get_entity_type(&self) -> &::std::option::Option<crate::types::TimeSeriesEntityType> {
        &self.entity_type
    }
    /// <p>The name of the time series data points form.</p>
    /// This field is required.
    pub fn form_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.form_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the time series data points form.</p>
    pub fn set_form_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.form_name = input;
        self
    }
    /// <p>The name of the time series data points form.</p>
    pub fn get_form_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.form_name
    }
    /// <p>The timestamp at which the data points that you want to list started.</p>
    pub fn started_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.started_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp at which the data points that you want to list started.</p>
    pub fn set_started_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.started_at = input;
        self
    }
    /// <p>The timestamp at which the data points that you want to list started.</p>
    pub fn get_started_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.started_at
    }
    /// <p>The timestamp at which the data points that you wanted to list ended.</p>
    pub fn ended_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.ended_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp at which the data points that you wanted to list ended.</p>
    pub fn set_ended_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.ended_at = input;
        self
    }
    /// <p>The timestamp at which the data points that you wanted to list ended.</p>
    pub fn get_ended_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.ended_at
    }
    /// <p>When the number of data points is greater than the default value for the MaxResults parameter, or if you explicitly specify a value for MaxResults that is less than the number of data points, the response includes a pagination token named NextToken. You can specify this NextToken value in a subsequent call to ListTimeSeriesDataPoints to list the next set of data points.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>When the number of data points is greater than the default value for the MaxResults parameter, or if you explicitly specify a value for MaxResults that is less than the number of data points, the response includes a pagination token named NextToken. You can specify this NextToken value in a subsequent call to ListTimeSeriesDataPoints to list the next set of data points.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>When the number of data points is greater than the default value for the MaxResults parameter, or if you explicitly specify a value for MaxResults that is less than the number of data points, the response includes a pagination token named NextToken. You can specify this NextToken value in a subsequent call to ListTimeSeriesDataPoints to list the next set of data points.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of data points to return in a single call to ListTimeSeriesDataPoints. When the number of data points to be listed is greater than the value of MaxResults, the response contains a NextToken value that you can use in a subsequent call to ListTimeSeriesDataPoints to list the next set of data points.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of data points to return in a single call to ListTimeSeriesDataPoints. When the number of data points to be listed is greater than the value of MaxResults, the response contains a NextToken value that you can use in a subsequent call to ListTimeSeriesDataPoints to list the next set of data points.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of data points to return in a single call to ListTimeSeriesDataPoints. When the number of data points to be listed is greater than the value of MaxResults, the response contains a NextToken value that you can use in a subsequent call to ListTimeSeriesDataPoints to list the next set of data points.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListTimeSeriesDataPointsInput`](crate::operation::list_time_series_data_points::ListTimeSeriesDataPointsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_time_series_data_points::ListTimeSeriesDataPointsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_time_series_data_points::ListTimeSeriesDataPointsInput {
            domain_identifier: self.domain_identifier,
            entity_identifier: self.entity_identifier,
            entity_type: self.entity_type,
            form_name: self.form_name,
            started_at: self.started_at,
            ended_at: self.ended_at,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
