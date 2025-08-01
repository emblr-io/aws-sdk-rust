// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeRefreshSchemasStatusOutput {
    /// <p>The status of the schema.</p>
    pub refresh_schemas_status: ::std::option::Option<crate::types::RefreshSchemasStatus>,
    _request_id: Option<String>,
}
impl DescribeRefreshSchemasStatusOutput {
    /// <p>The status of the schema.</p>
    pub fn refresh_schemas_status(&self) -> ::std::option::Option<&crate::types::RefreshSchemasStatus> {
        self.refresh_schemas_status.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeRefreshSchemasStatusOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeRefreshSchemasStatusOutput {
    /// Creates a new builder-style object to manufacture [`DescribeRefreshSchemasStatusOutput`](crate::operation::describe_refresh_schemas_status::DescribeRefreshSchemasStatusOutput).
    pub fn builder() -> crate::operation::describe_refresh_schemas_status::builders::DescribeRefreshSchemasStatusOutputBuilder {
        crate::operation::describe_refresh_schemas_status::builders::DescribeRefreshSchemasStatusOutputBuilder::default()
    }
}

/// A builder for [`DescribeRefreshSchemasStatusOutput`](crate::operation::describe_refresh_schemas_status::DescribeRefreshSchemasStatusOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeRefreshSchemasStatusOutputBuilder {
    pub(crate) refresh_schemas_status: ::std::option::Option<crate::types::RefreshSchemasStatus>,
    _request_id: Option<String>,
}
impl DescribeRefreshSchemasStatusOutputBuilder {
    /// <p>The status of the schema.</p>
    pub fn refresh_schemas_status(mut self, input: crate::types::RefreshSchemasStatus) -> Self {
        self.refresh_schemas_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the schema.</p>
    pub fn set_refresh_schemas_status(mut self, input: ::std::option::Option<crate::types::RefreshSchemasStatus>) -> Self {
        self.refresh_schemas_status = input;
        self
    }
    /// <p>The status of the schema.</p>
    pub fn get_refresh_schemas_status(&self) -> &::std::option::Option<crate::types::RefreshSchemasStatus> {
        &self.refresh_schemas_status
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeRefreshSchemasStatusOutput`](crate::operation::describe_refresh_schemas_status::DescribeRefreshSchemasStatusOutput).
    pub fn build(self) -> crate::operation::describe_refresh_schemas_status::DescribeRefreshSchemasStatusOutput {
        crate::operation::describe_refresh_schemas_status::DescribeRefreshSchemasStatusOutput {
            refresh_schemas_status: self.refresh_schemas_status,
            _request_id: self._request_id,
        }
    }
}
