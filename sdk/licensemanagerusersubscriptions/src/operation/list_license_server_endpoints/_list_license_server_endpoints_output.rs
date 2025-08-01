// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListLicenseServerEndpointsOutput {
    /// <p>An array of <code>LicenseServerEndpoint</code> resources that contain detailed information about the RDS License Servers that meet the request criteria.</p>
    pub license_server_endpoints: ::std::option::Option<::std::vec::Vec<crate::types::LicenseServerEndpoint>>,
    /// <p>The next token used for paginated responses. When this field isn't empty, there are additional elements that the service hasn't included in this request. Use this token with the next request to retrieve additional objects.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListLicenseServerEndpointsOutput {
    /// <p>An array of <code>LicenseServerEndpoint</code> resources that contain detailed information about the RDS License Servers that meet the request criteria.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.license_server_endpoints.is_none()`.
    pub fn license_server_endpoints(&self) -> &[crate::types::LicenseServerEndpoint] {
        self.license_server_endpoints.as_deref().unwrap_or_default()
    }
    /// <p>The next token used for paginated responses. When this field isn't empty, there are additional elements that the service hasn't included in this request. Use this token with the next request to retrieve additional objects.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListLicenseServerEndpointsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListLicenseServerEndpointsOutput {
    /// Creates a new builder-style object to manufacture [`ListLicenseServerEndpointsOutput`](crate::operation::list_license_server_endpoints::ListLicenseServerEndpointsOutput).
    pub fn builder() -> crate::operation::list_license_server_endpoints::builders::ListLicenseServerEndpointsOutputBuilder {
        crate::operation::list_license_server_endpoints::builders::ListLicenseServerEndpointsOutputBuilder::default()
    }
}

/// A builder for [`ListLicenseServerEndpointsOutput`](crate::operation::list_license_server_endpoints::ListLicenseServerEndpointsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListLicenseServerEndpointsOutputBuilder {
    pub(crate) license_server_endpoints: ::std::option::Option<::std::vec::Vec<crate::types::LicenseServerEndpoint>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListLicenseServerEndpointsOutputBuilder {
    /// Appends an item to `license_server_endpoints`.
    ///
    /// To override the contents of this collection use [`set_license_server_endpoints`](Self::set_license_server_endpoints).
    ///
    /// <p>An array of <code>LicenseServerEndpoint</code> resources that contain detailed information about the RDS License Servers that meet the request criteria.</p>
    pub fn license_server_endpoints(mut self, input: crate::types::LicenseServerEndpoint) -> Self {
        let mut v = self.license_server_endpoints.unwrap_or_default();
        v.push(input);
        self.license_server_endpoints = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of <code>LicenseServerEndpoint</code> resources that contain detailed information about the RDS License Servers that meet the request criteria.</p>
    pub fn set_license_server_endpoints(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::LicenseServerEndpoint>>) -> Self {
        self.license_server_endpoints = input;
        self
    }
    /// <p>An array of <code>LicenseServerEndpoint</code> resources that contain detailed information about the RDS License Servers that meet the request criteria.</p>
    pub fn get_license_server_endpoints(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::LicenseServerEndpoint>> {
        &self.license_server_endpoints
    }
    /// <p>The next token used for paginated responses. When this field isn't empty, there are additional elements that the service hasn't included in this request. Use this token with the next request to retrieve additional objects.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The next token used for paginated responses. When this field isn't empty, there are additional elements that the service hasn't included in this request. Use this token with the next request to retrieve additional objects.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The next token used for paginated responses. When this field isn't empty, there are additional elements that the service hasn't included in this request. Use this token with the next request to retrieve additional objects.</p>
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
    /// Consumes the builder and constructs a [`ListLicenseServerEndpointsOutput`](crate::operation::list_license_server_endpoints::ListLicenseServerEndpointsOutput).
    pub fn build(self) -> crate::operation::list_license_server_endpoints::ListLicenseServerEndpointsOutput {
        crate::operation::list_license_server_endpoints::ListLicenseServerEndpointsOutput {
            license_server_endpoints: self.license_server_endpoints,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
