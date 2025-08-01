// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetTimeSeriesDataPointOutput {
    /// <p>The ID of the Amazon DataZone domain that houses the asset data point that you want to get.</p>
    pub domain_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the asset for which you want to get the data point.</p>
    pub entity_id: ::std::option::Option<::std::string::String>,
    /// <p>The type of the asset for which you want to get the data point.</p>
    pub entity_type: ::std::option::Option<crate::types::TimeSeriesEntityType>,
    /// <p>The name of the time series form that houses the data point that you want to get.</p>
    pub form_name: ::std::option::Option<::std::string::String>,
    /// <p>The time series form that houses the data point that you want to get.</p>
    pub form: ::std::option::Option<crate::types::TimeSeriesDataPointFormOutput>,
    _request_id: Option<String>,
}
impl GetTimeSeriesDataPointOutput {
    /// <p>The ID of the Amazon DataZone domain that houses the asset data point that you want to get.</p>
    pub fn domain_id(&self) -> ::std::option::Option<&str> {
        self.domain_id.as_deref()
    }
    /// <p>The ID of the asset for which you want to get the data point.</p>
    pub fn entity_id(&self) -> ::std::option::Option<&str> {
        self.entity_id.as_deref()
    }
    /// <p>The type of the asset for which you want to get the data point.</p>
    pub fn entity_type(&self) -> ::std::option::Option<&crate::types::TimeSeriesEntityType> {
        self.entity_type.as_ref()
    }
    /// <p>The name of the time series form that houses the data point that you want to get.</p>
    pub fn form_name(&self) -> ::std::option::Option<&str> {
        self.form_name.as_deref()
    }
    /// <p>The time series form that houses the data point that you want to get.</p>
    pub fn form(&self) -> ::std::option::Option<&crate::types::TimeSeriesDataPointFormOutput> {
        self.form.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetTimeSeriesDataPointOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetTimeSeriesDataPointOutput {
    /// Creates a new builder-style object to manufacture [`GetTimeSeriesDataPointOutput`](crate::operation::get_time_series_data_point::GetTimeSeriesDataPointOutput).
    pub fn builder() -> crate::operation::get_time_series_data_point::builders::GetTimeSeriesDataPointOutputBuilder {
        crate::operation::get_time_series_data_point::builders::GetTimeSeriesDataPointOutputBuilder::default()
    }
}

/// A builder for [`GetTimeSeriesDataPointOutput`](crate::operation::get_time_series_data_point::GetTimeSeriesDataPointOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetTimeSeriesDataPointOutputBuilder {
    pub(crate) domain_id: ::std::option::Option<::std::string::String>,
    pub(crate) entity_id: ::std::option::Option<::std::string::String>,
    pub(crate) entity_type: ::std::option::Option<crate::types::TimeSeriesEntityType>,
    pub(crate) form_name: ::std::option::Option<::std::string::String>,
    pub(crate) form: ::std::option::Option<crate::types::TimeSeriesDataPointFormOutput>,
    _request_id: Option<String>,
}
impl GetTimeSeriesDataPointOutputBuilder {
    /// <p>The ID of the Amazon DataZone domain that houses the asset data point that you want to get.</p>
    pub fn domain_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Amazon DataZone domain that houses the asset data point that you want to get.</p>
    pub fn set_domain_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_id = input;
        self
    }
    /// <p>The ID of the Amazon DataZone domain that houses the asset data point that you want to get.</p>
    pub fn get_domain_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_id
    }
    /// <p>The ID of the asset for which you want to get the data point.</p>
    pub fn entity_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.entity_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the asset for which you want to get the data point.</p>
    pub fn set_entity_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.entity_id = input;
        self
    }
    /// <p>The ID of the asset for which you want to get the data point.</p>
    pub fn get_entity_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.entity_id
    }
    /// <p>The type of the asset for which you want to get the data point.</p>
    pub fn entity_type(mut self, input: crate::types::TimeSeriesEntityType) -> Self {
        self.entity_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of the asset for which you want to get the data point.</p>
    pub fn set_entity_type(mut self, input: ::std::option::Option<crate::types::TimeSeriesEntityType>) -> Self {
        self.entity_type = input;
        self
    }
    /// <p>The type of the asset for which you want to get the data point.</p>
    pub fn get_entity_type(&self) -> &::std::option::Option<crate::types::TimeSeriesEntityType> {
        &self.entity_type
    }
    /// <p>The name of the time series form that houses the data point that you want to get.</p>
    pub fn form_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.form_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the time series form that houses the data point that you want to get.</p>
    pub fn set_form_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.form_name = input;
        self
    }
    /// <p>The name of the time series form that houses the data point that you want to get.</p>
    pub fn get_form_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.form_name
    }
    /// <p>The time series form that houses the data point that you want to get.</p>
    pub fn form(mut self, input: crate::types::TimeSeriesDataPointFormOutput) -> Self {
        self.form = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time series form that houses the data point that you want to get.</p>
    pub fn set_form(mut self, input: ::std::option::Option<crate::types::TimeSeriesDataPointFormOutput>) -> Self {
        self.form = input;
        self
    }
    /// <p>The time series form that houses the data point that you want to get.</p>
    pub fn get_form(&self) -> &::std::option::Option<crate::types::TimeSeriesDataPointFormOutput> {
        &self.form
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetTimeSeriesDataPointOutput`](crate::operation::get_time_series_data_point::GetTimeSeriesDataPointOutput).
    pub fn build(self) -> crate::operation::get_time_series_data_point::GetTimeSeriesDataPointOutput {
        crate::operation::get_time_series_data_point::GetTimeSeriesDataPointOutput {
            domain_id: self.domain_id,
            entity_id: self.entity_id,
            entity_type: self.entity_type,
            form_name: self.form_name,
            form: self.form,
            _request_id: self._request_id,
        }
    }
}
