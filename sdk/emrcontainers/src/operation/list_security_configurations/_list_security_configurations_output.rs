// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListSecurityConfigurationsOutput {
    /// <p>The list of returned security configurations.</p>
    pub security_configurations: ::std::option::Option<::std::vec::Vec<crate::types::SecurityConfiguration>>,
    /// <p>The token for the next set of security configurations to return.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListSecurityConfigurationsOutput {
    /// <p>The list of returned security configurations.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.security_configurations.is_none()`.
    pub fn security_configurations(&self) -> &[crate::types::SecurityConfiguration] {
        self.security_configurations.as_deref().unwrap_or_default()
    }
    /// <p>The token for the next set of security configurations to return.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListSecurityConfigurationsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListSecurityConfigurationsOutput {
    /// Creates a new builder-style object to manufacture [`ListSecurityConfigurationsOutput`](crate::operation::list_security_configurations::ListSecurityConfigurationsOutput).
    pub fn builder() -> crate::operation::list_security_configurations::builders::ListSecurityConfigurationsOutputBuilder {
        crate::operation::list_security_configurations::builders::ListSecurityConfigurationsOutputBuilder::default()
    }
}

/// A builder for [`ListSecurityConfigurationsOutput`](crate::operation::list_security_configurations::ListSecurityConfigurationsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListSecurityConfigurationsOutputBuilder {
    pub(crate) security_configurations: ::std::option::Option<::std::vec::Vec<crate::types::SecurityConfiguration>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListSecurityConfigurationsOutputBuilder {
    /// Appends an item to `security_configurations`.
    ///
    /// To override the contents of this collection use [`set_security_configurations`](Self::set_security_configurations).
    ///
    /// <p>The list of returned security configurations.</p>
    pub fn security_configurations(mut self, input: crate::types::SecurityConfiguration) -> Self {
        let mut v = self.security_configurations.unwrap_or_default();
        v.push(input);
        self.security_configurations = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of returned security configurations.</p>
    pub fn set_security_configurations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SecurityConfiguration>>) -> Self {
        self.security_configurations = input;
        self
    }
    /// <p>The list of returned security configurations.</p>
    pub fn get_security_configurations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SecurityConfiguration>> {
        &self.security_configurations
    }
    /// <p>The token for the next set of security configurations to return.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token for the next set of security configurations to return.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token for the next set of security configurations to return.</p>
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
    /// Consumes the builder and constructs a [`ListSecurityConfigurationsOutput`](crate::operation::list_security_configurations::ListSecurityConfigurationsOutput).
    pub fn build(self) -> crate::operation::list_security_configurations::ListSecurityConfigurationsOutput {
        crate::operation::list_security_configurations::ListSecurityConfigurationsOutput {
            security_configurations: self.security_configurations,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
