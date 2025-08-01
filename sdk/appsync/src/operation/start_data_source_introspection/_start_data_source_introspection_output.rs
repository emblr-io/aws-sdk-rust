// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartDataSourceIntrospectionOutput {
    /// <p>The introspection ID. Each introspection contains a unique ID that can be used to reference the instrospection record.</p>
    pub introspection_id: ::std::option::Option<::std::string::String>,
    /// <p>The status of the introspection during creation. By default, when a new instrospection has been created, the status will be set to <code>PROCESSING</code>. Once the operation has been completed, the status will change to <code>SUCCESS</code> or <code>FAILED</code> depending on how the data was parsed. A <code>FAILED</code> operation will return an error and its details as an <code>introspectionStatusDetail</code>.</p>
    pub introspection_status: ::std::option::Option<crate::types::DataSourceIntrospectionStatus>,
    /// <p>The error detail field. When a <code>FAILED</code> <code>introspectionStatus</code> is returned, the <code>introspectionStatusDetail</code> will also return the exact error that was generated during the operation.</p>
    pub introspection_status_detail: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl StartDataSourceIntrospectionOutput {
    /// <p>The introspection ID. Each introspection contains a unique ID that can be used to reference the instrospection record.</p>
    pub fn introspection_id(&self) -> ::std::option::Option<&str> {
        self.introspection_id.as_deref()
    }
    /// <p>The status of the introspection during creation. By default, when a new instrospection has been created, the status will be set to <code>PROCESSING</code>. Once the operation has been completed, the status will change to <code>SUCCESS</code> or <code>FAILED</code> depending on how the data was parsed. A <code>FAILED</code> operation will return an error and its details as an <code>introspectionStatusDetail</code>.</p>
    pub fn introspection_status(&self) -> ::std::option::Option<&crate::types::DataSourceIntrospectionStatus> {
        self.introspection_status.as_ref()
    }
    /// <p>The error detail field. When a <code>FAILED</code> <code>introspectionStatus</code> is returned, the <code>introspectionStatusDetail</code> will also return the exact error that was generated during the operation.</p>
    pub fn introspection_status_detail(&self) -> ::std::option::Option<&str> {
        self.introspection_status_detail.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for StartDataSourceIntrospectionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl StartDataSourceIntrospectionOutput {
    /// Creates a new builder-style object to manufacture [`StartDataSourceIntrospectionOutput`](crate::operation::start_data_source_introspection::StartDataSourceIntrospectionOutput).
    pub fn builder() -> crate::operation::start_data_source_introspection::builders::StartDataSourceIntrospectionOutputBuilder {
        crate::operation::start_data_source_introspection::builders::StartDataSourceIntrospectionOutputBuilder::default()
    }
}

/// A builder for [`StartDataSourceIntrospectionOutput`](crate::operation::start_data_source_introspection::StartDataSourceIntrospectionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartDataSourceIntrospectionOutputBuilder {
    pub(crate) introspection_id: ::std::option::Option<::std::string::String>,
    pub(crate) introspection_status: ::std::option::Option<crate::types::DataSourceIntrospectionStatus>,
    pub(crate) introspection_status_detail: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl StartDataSourceIntrospectionOutputBuilder {
    /// <p>The introspection ID. Each introspection contains a unique ID that can be used to reference the instrospection record.</p>
    pub fn introspection_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.introspection_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The introspection ID. Each introspection contains a unique ID that can be used to reference the instrospection record.</p>
    pub fn set_introspection_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.introspection_id = input;
        self
    }
    /// <p>The introspection ID. Each introspection contains a unique ID that can be used to reference the instrospection record.</p>
    pub fn get_introspection_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.introspection_id
    }
    /// <p>The status of the introspection during creation. By default, when a new instrospection has been created, the status will be set to <code>PROCESSING</code>. Once the operation has been completed, the status will change to <code>SUCCESS</code> or <code>FAILED</code> depending on how the data was parsed. A <code>FAILED</code> operation will return an error and its details as an <code>introspectionStatusDetail</code>.</p>
    pub fn introspection_status(mut self, input: crate::types::DataSourceIntrospectionStatus) -> Self {
        self.introspection_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the introspection during creation. By default, when a new instrospection has been created, the status will be set to <code>PROCESSING</code>. Once the operation has been completed, the status will change to <code>SUCCESS</code> or <code>FAILED</code> depending on how the data was parsed. A <code>FAILED</code> operation will return an error and its details as an <code>introspectionStatusDetail</code>.</p>
    pub fn set_introspection_status(mut self, input: ::std::option::Option<crate::types::DataSourceIntrospectionStatus>) -> Self {
        self.introspection_status = input;
        self
    }
    /// <p>The status of the introspection during creation. By default, when a new instrospection has been created, the status will be set to <code>PROCESSING</code>. Once the operation has been completed, the status will change to <code>SUCCESS</code> or <code>FAILED</code> depending on how the data was parsed. A <code>FAILED</code> operation will return an error and its details as an <code>introspectionStatusDetail</code>.</p>
    pub fn get_introspection_status(&self) -> &::std::option::Option<crate::types::DataSourceIntrospectionStatus> {
        &self.introspection_status
    }
    /// <p>The error detail field. When a <code>FAILED</code> <code>introspectionStatus</code> is returned, the <code>introspectionStatusDetail</code> will also return the exact error that was generated during the operation.</p>
    pub fn introspection_status_detail(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.introspection_status_detail = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The error detail field. When a <code>FAILED</code> <code>introspectionStatus</code> is returned, the <code>introspectionStatusDetail</code> will also return the exact error that was generated during the operation.</p>
    pub fn set_introspection_status_detail(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.introspection_status_detail = input;
        self
    }
    /// <p>The error detail field. When a <code>FAILED</code> <code>introspectionStatus</code> is returned, the <code>introspectionStatusDetail</code> will also return the exact error that was generated during the operation.</p>
    pub fn get_introspection_status_detail(&self) -> &::std::option::Option<::std::string::String> {
        &self.introspection_status_detail
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`StartDataSourceIntrospectionOutput`](crate::operation::start_data_source_introspection::StartDataSourceIntrospectionOutput).
    pub fn build(self) -> crate::operation::start_data_source_introspection::StartDataSourceIntrospectionOutput {
        crate::operation::start_data_source_introspection::StartDataSourceIntrospectionOutput {
            introspection_id: self.introspection_id,
            introspection_status: self.introspection_status,
            introspection_status_detail: self.introspection_status_detail,
            _request_id: self._request_id,
        }
    }
}
