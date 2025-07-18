// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListServicesOutput {
    /// <p>A list of service summary information records. In a paginated request, the request returns up to <code>MaxResults</code> records for each call.</p>
    pub service_summary_list: ::std::vec::Vec<crate::types::ServiceSummary>,
    /// <p>The token that you can pass in a subsequent request to get the next result page. It's returned in a paginated request.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListServicesOutput {
    /// <p>A list of service summary information records. In a paginated request, the request returns up to <code>MaxResults</code> records for each call.</p>
    pub fn service_summary_list(&self) -> &[crate::types::ServiceSummary] {
        use std::ops::Deref;
        self.service_summary_list.deref()
    }
    /// <p>The token that you can pass in a subsequent request to get the next result page. It's returned in a paginated request.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListServicesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListServicesOutput {
    /// Creates a new builder-style object to manufacture [`ListServicesOutput`](crate::operation::list_services::ListServicesOutput).
    pub fn builder() -> crate::operation::list_services::builders::ListServicesOutputBuilder {
        crate::operation::list_services::builders::ListServicesOutputBuilder::default()
    }
}

/// A builder for [`ListServicesOutput`](crate::operation::list_services::ListServicesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListServicesOutputBuilder {
    pub(crate) service_summary_list: ::std::option::Option<::std::vec::Vec<crate::types::ServiceSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListServicesOutputBuilder {
    /// Appends an item to `service_summary_list`.
    ///
    /// To override the contents of this collection use [`set_service_summary_list`](Self::set_service_summary_list).
    ///
    /// <p>A list of service summary information records. In a paginated request, the request returns up to <code>MaxResults</code> records for each call.</p>
    pub fn service_summary_list(mut self, input: crate::types::ServiceSummary) -> Self {
        let mut v = self.service_summary_list.unwrap_or_default();
        v.push(input);
        self.service_summary_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of service summary information records. In a paginated request, the request returns up to <code>MaxResults</code> records for each call.</p>
    pub fn set_service_summary_list(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ServiceSummary>>) -> Self {
        self.service_summary_list = input;
        self
    }
    /// <p>A list of service summary information records. In a paginated request, the request returns up to <code>MaxResults</code> records for each call.</p>
    pub fn get_service_summary_list(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ServiceSummary>> {
        &self.service_summary_list
    }
    /// <p>The token that you can pass in a subsequent request to get the next result page. It's returned in a paginated request.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token that you can pass in a subsequent request to get the next result page. It's returned in a paginated request.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token that you can pass in a subsequent request to get the next result page. It's returned in a paginated request.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListServicesOutput`](crate::operation::list_services::ListServicesOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`service_summary_list`](crate::operation::list_services::builders::ListServicesOutputBuilder::service_summary_list)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_services::ListServicesOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_services::ListServicesOutput {
            service_summary_list: self.service_summary_list.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "service_summary_list",
                    "service_summary_list was not specified but it is required when building ListServicesOutput",
                )
            })?,
            next_token: self.next_token,
            _request_id: self._request_id,
        })
    }
}
