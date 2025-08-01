// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetRateBasedStatementManagedKeysOutput {
    /// <p>The keys that are of Internet Protocol version 4 (IPv4).</p>
    pub managed_keys_ipv4: ::std::option::Option<crate::types::RateBasedStatementManagedKeysIpSet>,
    /// <p>The keys that are of Internet Protocol version 6 (IPv6).</p>
    pub managed_keys_ipv6: ::std::option::Option<crate::types::RateBasedStatementManagedKeysIpSet>,
    _request_id: Option<String>,
}
impl GetRateBasedStatementManagedKeysOutput {
    /// <p>The keys that are of Internet Protocol version 4 (IPv4).</p>
    pub fn managed_keys_ipv4(&self) -> ::std::option::Option<&crate::types::RateBasedStatementManagedKeysIpSet> {
        self.managed_keys_ipv4.as_ref()
    }
    /// <p>The keys that are of Internet Protocol version 6 (IPv6).</p>
    pub fn managed_keys_ipv6(&self) -> ::std::option::Option<&crate::types::RateBasedStatementManagedKeysIpSet> {
        self.managed_keys_ipv6.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetRateBasedStatementManagedKeysOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetRateBasedStatementManagedKeysOutput {
    /// Creates a new builder-style object to manufacture [`GetRateBasedStatementManagedKeysOutput`](crate::operation::get_rate_based_statement_managed_keys::GetRateBasedStatementManagedKeysOutput).
    pub fn builder() -> crate::operation::get_rate_based_statement_managed_keys::builders::GetRateBasedStatementManagedKeysOutputBuilder {
        crate::operation::get_rate_based_statement_managed_keys::builders::GetRateBasedStatementManagedKeysOutputBuilder::default()
    }
}

/// A builder for [`GetRateBasedStatementManagedKeysOutput`](crate::operation::get_rate_based_statement_managed_keys::GetRateBasedStatementManagedKeysOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetRateBasedStatementManagedKeysOutputBuilder {
    pub(crate) managed_keys_ipv4: ::std::option::Option<crate::types::RateBasedStatementManagedKeysIpSet>,
    pub(crate) managed_keys_ipv6: ::std::option::Option<crate::types::RateBasedStatementManagedKeysIpSet>,
    _request_id: Option<String>,
}
impl GetRateBasedStatementManagedKeysOutputBuilder {
    /// <p>The keys that are of Internet Protocol version 4 (IPv4).</p>
    pub fn managed_keys_ipv4(mut self, input: crate::types::RateBasedStatementManagedKeysIpSet) -> Self {
        self.managed_keys_ipv4 = ::std::option::Option::Some(input);
        self
    }
    /// <p>The keys that are of Internet Protocol version 4 (IPv4).</p>
    pub fn set_managed_keys_ipv4(mut self, input: ::std::option::Option<crate::types::RateBasedStatementManagedKeysIpSet>) -> Self {
        self.managed_keys_ipv4 = input;
        self
    }
    /// <p>The keys that are of Internet Protocol version 4 (IPv4).</p>
    pub fn get_managed_keys_ipv4(&self) -> &::std::option::Option<crate::types::RateBasedStatementManagedKeysIpSet> {
        &self.managed_keys_ipv4
    }
    /// <p>The keys that are of Internet Protocol version 6 (IPv6).</p>
    pub fn managed_keys_ipv6(mut self, input: crate::types::RateBasedStatementManagedKeysIpSet) -> Self {
        self.managed_keys_ipv6 = ::std::option::Option::Some(input);
        self
    }
    /// <p>The keys that are of Internet Protocol version 6 (IPv6).</p>
    pub fn set_managed_keys_ipv6(mut self, input: ::std::option::Option<crate::types::RateBasedStatementManagedKeysIpSet>) -> Self {
        self.managed_keys_ipv6 = input;
        self
    }
    /// <p>The keys that are of Internet Protocol version 6 (IPv6).</p>
    pub fn get_managed_keys_ipv6(&self) -> &::std::option::Option<crate::types::RateBasedStatementManagedKeysIpSet> {
        &self.managed_keys_ipv6
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetRateBasedStatementManagedKeysOutput`](crate::operation::get_rate_based_statement_managed_keys::GetRateBasedStatementManagedKeysOutput).
    pub fn build(self) -> crate::operation::get_rate_based_statement_managed_keys::GetRateBasedStatementManagedKeysOutput {
        crate::operation::get_rate_based_statement_managed_keys::GetRateBasedStatementManagedKeysOutput {
            managed_keys_ipv4: self.managed_keys_ipv4,
            managed_keys_ipv6: self.managed_keys_ipv6,
            _request_id: self._request_id,
        }
    }
}
