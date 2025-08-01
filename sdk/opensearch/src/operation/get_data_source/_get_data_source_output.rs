// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The result of a <code>GetDataSource</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetDataSourceOutput {
    /// <p>The type of data source.</p>
    pub data_source_type: ::std::option::Option<crate::types::DataSourceType>,
    /// <p>The name of the data source.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>A description of the data source.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The status of the data source.</p>
    pub status: ::std::option::Option<crate::types::DataSourceStatus>,
    _request_id: Option<String>,
}
impl GetDataSourceOutput {
    /// <p>The type of data source.</p>
    pub fn data_source_type(&self) -> ::std::option::Option<&crate::types::DataSourceType> {
        self.data_source_type.as_ref()
    }
    /// <p>The name of the data source.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>A description of the data source.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The status of the data source.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::DataSourceStatus> {
        self.status.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetDataSourceOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetDataSourceOutput {
    /// Creates a new builder-style object to manufacture [`GetDataSourceOutput`](crate::operation::get_data_source::GetDataSourceOutput).
    pub fn builder() -> crate::operation::get_data_source::builders::GetDataSourceOutputBuilder {
        crate::operation::get_data_source::builders::GetDataSourceOutputBuilder::default()
    }
}

/// A builder for [`GetDataSourceOutput`](crate::operation::get_data_source::GetDataSourceOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetDataSourceOutputBuilder {
    pub(crate) data_source_type: ::std::option::Option<crate::types::DataSourceType>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::DataSourceStatus>,
    _request_id: Option<String>,
}
impl GetDataSourceOutputBuilder {
    /// <p>The type of data source.</p>
    pub fn data_source_type(mut self, input: crate::types::DataSourceType) -> Self {
        self.data_source_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of data source.</p>
    pub fn set_data_source_type(mut self, input: ::std::option::Option<crate::types::DataSourceType>) -> Self {
        self.data_source_type = input;
        self
    }
    /// <p>The type of data source.</p>
    pub fn get_data_source_type(&self) -> &::std::option::Option<crate::types::DataSourceType> {
        &self.data_source_type
    }
    /// <p>The name of the data source.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the data source.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the data source.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>A description of the data source.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description of the data source.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description of the data source.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The status of the data source.</p>
    pub fn status(mut self, input: crate::types::DataSourceStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the data source.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::DataSourceStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the data source.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::DataSourceStatus> {
        &self.status
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetDataSourceOutput`](crate::operation::get_data_source::GetDataSourceOutput).
    pub fn build(self) -> crate::operation::get_data_source::GetDataSourceOutput {
        crate::operation::get_data_source::GetDataSourceOutput {
            data_source_type: self.data_source_type,
            name: self.name,
            description: self.description,
            status: self.status,
            _request_id: self._request_id,
        }
    }
}
