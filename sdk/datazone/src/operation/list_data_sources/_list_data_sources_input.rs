// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct ListDataSourcesInput {
    /// <p>The identifier of the Amazon DataZone domain in which to list the data sources.</p>
    pub domain_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the project in which to list data sources.</p>
    pub project_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the environment in which to list the data sources.</p>
    pub environment_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the connection.</p>
    pub connection_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The type of the data source.</p>
    pub r#type: ::std::option::Option<::std::string::String>,
    /// <p>The status of the data source.</p>
    pub status: ::std::option::Option<crate::types::DataSourceStatus>,
    /// <p>The name of the data source.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>When the number of data sources is greater than the default value for the <code>MaxResults</code> parameter, or if you explicitly specify a value for <code>MaxResults</code> that is less than the number of data sources, the response includes a pagination token named <code>NextToken</code>. You can specify this <code>NextToken</code> value in a subsequent call to <code>ListDataSources</code> to list the next set of data sources.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of data sources to return in a single call to <code>ListDataSources</code>. When the number of data sources to be listed is greater than the value of <code>MaxResults</code>, the response contains a <code>NextToken</code> value that you can use in a subsequent call to <code>ListDataSources</code> to list the next set of data sources.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListDataSourcesInput {
    /// <p>The identifier of the Amazon DataZone domain in which to list the data sources.</p>
    pub fn domain_identifier(&self) -> ::std::option::Option<&str> {
        self.domain_identifier.as_deref()
    }
    /// <p>The identifier of the project in which to list data sources.</p>
    pub fn project_identifier(&self) -> ::std::option::Option<&str> {
        self.project_identifier.as_deref()
    }
    /// <p>The identifier of the environment in which to list the data sources.</p>
    pub fn environment_identifier(&self) -> ::std::option::Option<&str> {
        self.environment_identifier.as_deref()
    }
    /// <p>The ID of the connection.</p>
    pub fn connection_identifier(&self) -> ::std::option::Option<&str> {
        self.connection_identifier.as_deref()
    }
    /// <p>The type of the data source.</p>
    pub fn r#type(&self) -> ::std::option::Option<&str> {
        self.r#type.as_deref()
    }
    /// <p>The status of the data source.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::DataSourceStatus> {
        self.status.as_ref()
    }
    /// <p>The name of the data source.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>When the number of data sources is greater than the default value for the <code>MaxResults</code> parameter, or if you explicitly specify a value for <code>MaxResults</code> that is less than the number of data sources, the response includes a pagination token named <code>NextToken</code>. You can specify this <code>NextToken</code> value in a subsequent call to <code>ListDataSources</code> to list the next set of data sources.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of data sources to return in a single call to <code>ListDataSources</code>. When the number of data sources to be listed is greater than the value of <code>MaxResults</code>, the response contains a <code>NextToken</code> value that you can use in a subsequent call to <code>ListDataSources</code> to list the next set of data sources.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ::std::fmt::Debug for ListDataSourcesInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("ListDataSourcesInput");
        formatter.field("domain_identifier", &self.domain_identifier);
        formatter.field("project_identifier", &self.project_identifier);
        formatter.field("environment_identifier", &self.environment_identifier);
        formatter.field("connection_identifier", &self.connection_identifier);
        formatter.field("r#type", &self.r#type);
        formatter.field("status", &self.status);
        formatter.field("name", &"*** Sensitive Data Redacted ***");
        formatter.field("next_token", &self.next_token);
        formatter.field("max_results", &self.max_results);
        formatter.finish()
    }
}
impl ListDataSourcesInput {
    /// Creates a new builder-style object to manufacture [`ListDataSourcesInput`](crate::operation::list_data_sources::ListDataSourcesInput).
    pub fn builder() -> crate::operation::list_data_sources::builders::ListDataSourcesInputBuilder {
        crate::operation::list_data_sources::builders::ListDataSourcesInputBuilder::default()
    }
}

/// A builder for [`ListDataSourcesInput`](crate::operation::list_data_sources::ListDataSourcesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct ListDataSourcesInputBuilder {
    pub(crate) domain_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) project_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) environment_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) connection_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::DataSourceStatus>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListDataSourcesInputBuilder {
    /// <p>The identifier of the Amazon DataZone domain in which to list the data sources.</p>
    /// This field is required.
    pub fn domain_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the Amazon DataZone domain in which to list the data sources.</p>
    pub fn set_domain_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_identifier = input;
        self
    }
    /// <p>The identifier of the Amazon DataZone domain in which to list the data sources.</p>
    pub fn get_domain_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_identifier
    }
    /// <p>The identifier of the project in which to list data sources.</p>
    /// This field is required.
    pub fn project_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.project_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the project in which to list data sources.</p>
    pub fn set_project_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.project_identifier = input;
        self
    }
    /// <p>The identifier of the project in which to list data sources.</p>
    pub fn get_project_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.project_identifier
    }
    /// <p>The identifier of the environment in which to list the data sources.</p>
    pub fn environment_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.environment_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the environment in which to list the data sources.</p>
    pub fn set_environment_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.environment_identifier = input;
        self
    }
    /// <p>The identifier of the environment in which to list the data sources.</p>
    pub fn get_environment_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.environment_identifier
    }
    /// <p>The ID of the connection.</p>
    pub fn connection_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.connection_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the connection.</p>
    pub fn set_connection_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.connection_identifier = input;
        self
    }
    /// <p>The ID of the connection.</p>
    pub fn get_connection_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.connection_identifier
    }
    /// <p>The type of the data source.</p>
    pub fn r#type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.r#type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The type of the data source.</p>
    pub fn set_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of the data source.</p>
    pub fn get_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.r#type
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
    /// <p>When the number of data sources is greater than the default value for the <code>MaxResults</code> parameter, or if you explicitly specify a value for <code>MaxResults</code> that is less than the number of data sources, the response includes a pagination token named <code>NextToken</code>. You can specify this <code>NextToken</code> value in a subsequent call to <code>ListDataSources</code> to list the next set of data sources.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>When the number of data sources is greater than the default value for the <code>MaxResults</code> parameter, or if you explicitly specify a value for <code>MaxResults</code> that is less than the number of data sources, the response includes a pagination token named <code>NextToken</code>. You can specify this <code>NextToken</code> value in a subsequent call to <code>ListDataSources</code> to list the next set of data sources.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>When the number of data sources is greater than the default value for the <code>MaxResults</code> parameter, or if you explicitly specify a value for <code>MaxResults</code> that is less than the number of data sources, the response includes a pagination token named <code>NextToken</code>. You can specify this <code>NextToken</code> value in a subsequent call to <code>ListDataSources</code> to list the next set of data sources.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of data sources to return in a single call to <code>ListDataSources</code>. When the number of data sources to be listed is greater than the value of <code>MaxResults</code>, the response contains a <code>NextToken</code> value that you can use in a subsequent call to <code>ListDataSources</code> to list the next set of data sources.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of data sources to return in a single call to <code>ListDataSources</code>. When the number of data sources to be listed is greater than the value of <code>MaxResults</code>, the response contains a <code>NextToken</code> value that you can use in a subsequent call to <code>ListDataSources</code> to list the next set of data sources.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of data sources to return in a single call to <code>ListDataSources</code>. When the number of data sources to be listed is greater than the value of <code>MaxResults</code>, the response contains a <code>NextToken</code> value that you can use in a subsequent call to <code>ListDataSources</code> to list the next set of data sources.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListDataSourcesInput`](crate::operation::list_data_sources::ListDataSourcesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_data_sources::ListDataSourcesInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_data_sources::ListDataSourcesInput {
            domain_identifier: self.domain_identifier,
            project_identifier: self.project_identifier,
            environment_identifier: self.environment_identifier,
            connection_identifier: self.connection_identifier,
            r#type: self.r#type,
            status: self.status,
            name: self.name,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
impl ::std::fmt::Debug for ListDataSourcesInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("ListDataSourcesInputBuilder");
        formatter.field("domain_identifier", &self.domain_identifier);
        formatter.field("project_identifier", &self.project_identifier);
        formatter.field("environment_identifier", &self.environment_identifier);
        formatter.field("connection_identifier", &self.connection_identifier);
        formatter.field("r#type", &self.r#type);
        formatter.field("status", &self.status);
        formatter.field("name", &"*** Sensitive Data Redacted ***");
        formatter.field("next_token", &self.next_token);
        formatter.field("max_results", &self.max_results);
        formatter.finish()
    }
}
