// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListServicesOutput {
    /// <p>An array that contains one <code>ServiceSummary</code> object for each service that matches the specified filter criteria.</p>
    pub services: ::std::option::Option<::std::vec::Vec<crate::types::ServiceSummary>>,
    /// <p>If the response contains <code>NextToken</code>, submit another <code>ListServices</code> request to get the next group of results. Specify the value of <code>NextToken</code> from the previous response in the next request.</p><note>
    /// <p>Cloud Map gets <code>MaxResults</code> services and then filters them based on the specified criteria. It's possible that no services in the first <code>MaxResults</code> services matched the specified criteria but that subsequent groups of <code>MaxResults</code> services do contain services that match the criteria.</p>
    /// </note>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListServicesOutput {
    /// <p>An array that contains one <code>ServiceSummary</code> object for each service that matches the specified filter criteria.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.services.is_none()`.
    pub fn services(&self) -> &[crate::types::ServiceSummary] {
        self.services.as_deref().unwrap_or_default()
    }
    /// <p>If the response contains <code>NextToken</code>, submit another <code>ListServices</code> request to get the next group of results. Specify the value of <code>NextToken</code> from the previous response in the next request.</p><note>
    /// <p>Cloud Map gets <code>MaxResults</code> services and then filters them based on the specified criteria. It's possible that no services in the first <code>MaxResults</code> services matched the specified criteria but that subsequent groups of <code>MaxResults</code> services do contain services that match the criteria.</p>
    /// </note>
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
    pub(crate) services: ::std::option::Option<::std::vec::Vec<crate::types::ServiceSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListServicesOutputBuilder {
    /// Appends an item to `services`.
    ///
    /// To override the contents of this collection use [`set_services`](Self::set_services).
    ///
    /// <p>An array that contains one <code>ServiceSummary</code> object for each service that matches the specified filter criteria.</p>
    pub fn services(mut self, input: crate::types::ServiceSummary) -> Self {
        let mut v = self.services.unwrap_or_default();
        v.push(input);
        self.services = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array that contains one <code>ServiceSummary</code> object for each service that matches the specified filter criteria.</p>
    pub fn set_services(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ServiceSummary>>) -> Self {
        self.services = input;
        self
    }
    /// <p>An array that contains one <code>ServiceSummary</code> object for each service that matches the specified filter criteria.</p>
    pub fn get_services(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ServiceSummary>> {
        &self.services
    }
    /// <p>If the response contains <code>NextToken</code>, submit another <code>ListServices</code> request to get the next group of results. Specify the value of <code>NextToken</code> from the previous response in the next request.</p><note>
    /// <p>Cloud Map gets <code>MaxResults</code> services and then filters them based on the specified criteria. It's possible that no services in the first <code>MaxResults</code> services matched the specified criteria but that subsequent groups of <code>MaxResults</code> services do contain services that match the criteria.</p>
    /// </note>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the response contains <code>NextToken</code>, submit another <code>ListServices</code> request to get the next group of results. Specify the value of <code>NextToken</code> from the previous response in the next request.</p><note>
    /// <p>Cloud Map gets <code>MaxResults</code> services and then filters them based on the specified criteria. It's possible that no services in the first <code>MaxResults</code> services matched the specified criteria but that subsequent groups of <code>MaxResults</code> services do contain services that match the criteria.</p>
    /// </note>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If the response contains <code>NextToken</code>, submit another <code>ListServices</code> request to get the next group of results. Specify the value of <code>NextToken</code> from the previous response in the next request.</p><note>
    /// <p>Cloud Map gets <code>MaxResults</code> services and then filters them based on the specified criteria. It's possible that no services in the first <code>MaxResults</code> services matched the specified criteria but that subsequent groups of <code>MaxResults</code> services do contain services that match the criteria.</p>
    /// </note>
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
    pub fn build(self) -> crate::operation::list_services::ListServicesOutput {
        crate::operation::list_services::ListServicesOutput {
            services: self.services,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
